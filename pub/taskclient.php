<?php

$GLOBALS[ "uname"    ] = trim(`uname`);
$GLOBALS[ "hostname" ] = trim(`hostname`);

$GLOBALS[ "server_host" ] = "xberry.org";
$GLOBALS[ "server_port" ] = 11042;

function Logflush()
{
	if (isset($GLOBALS[ "logfd" ])) fflush($GLOBALS[ "logfd" ]);
}

function Logdat($message)
{
	$logfile = "../log/taskclient.log";
	
	if (! isset($GLOBALS[ "logfd" ]))
	{
		if (file_exists($logfile))
		{
			$GLOBALS[ "logdt" ] = date("Ymd",filemtime($logfile));
		}
		else
		{
			$GLOBALS[ "logdt" ] = date("Ymd");
		}
		
		$GLOBALS[ "logfd" ] = fopen($logfile,"a");

		if (! $GLOBALS[ "logfd" ])
		{
			echo "Cannot open logfile...\n";
			exit();
		}

		chmod($logfile,0666);
	}
	
	if ($GLOBALS[ "logdt" ] != date("Ymd"))
	{
		//
		// Log file expired, re-open.
		//
		
		fclose($GLOBALS[ "logfd" ]);
		
		rename($logfile,substr($logfile,0,-4) . "." . $GLOBALS[ "logdt" ] . ".log");
		
		$GLOBALS[ "logfd" ] = fopen($logfile,"a");
		$GLOBALS[ "logdt" ] = date("Ymd",filemtime($logfile));
		
		chmod($logfile,0666);
	}
	
	fputs($GLOBALS[ "logfd" ],$message);
}

function EncodeMessage($message)
{
	$json = json_encode($message);
	$jlen = strlen($json);
	
	$packet = chr(($jlen >> 24) & 0xff) . chr(($jlen >> 16) & 0xff)
			. chr(($jlen >>  8) & 0xff) . chr(($jlen >>  0) & 0xff)
			. $json;
			
	return $packet;
}

function IP2Bin($ip)
{
	$parts = explode(".",$ip);
	if (count($parts) != 4) return 0;
	
	$bin = (intval($parts[ 0 ]) << 24)
		 + (intval($parts[ 1 ]) << 16)
		 + (intval($parts[ 2 ]) <<  8)
		 + (intval($parts[ 3 ]) <<  0)
		 ;
		 
	return $bin;
}

function Bin2IP($bin)
{
	$ip = (($bin >> 24) & 0xff)
		. "."
		. (($bin >> 16) & 0xff)
		. "."
		. (($bin >>  8) & 0xff)
		. "."
		. (($bin >>  0) & 0xff)
		; 

	return $ip;
}

function IP($ip)
{
	return Bin2IP(IP2Bin($ip));
}

function IPZero($ip)
{	
	$bin = strpos($ip,".") ? IP2Bin($ip) : $ip;
	
	$ip = str_pad((($bin >> 24) & 0xff),3,"0",STR_PAD_LEFT)
		. "."
		. str_pad((($bin >> 16) & 0xff),3,"0",STR_PAD_LEFT)
		. "."
		. str_pad((($bin >>  8) & 0xff),3,"0",STR_PAD_LEFT)
		. "."
		. str_pad((($bin >>  0) & 0xff),3,"0",STR_PAD_LEFT)
		; 

	return $ip;
}

function Ping($host,$timeout = 100,$quiet = true)
{
	if (isset($GLOBALS[ "sudo" ]))
	{
		return SudoPing($host,$timeout,$quiet);
	}
	
	return UserPing($host);
}

function UserPing($host,$timeout = 1000,$quiet = true)
{
	$timeout = floor($timeout / 1000);
	if ($timeout <= 0) $timeout = 1;
	
	if ($GLOBALS[ "uname" ] == "Darwin")
	{
		exec("ping -c 1 -t $timeout $host",$lines,$return);
	}
	else
	{
		exec("ping -c 1 -W $timeout $host",$lines,$return);
	}
	
	if ($return == 0)
	{
		$lines = implode("\n",$lines);
		
		if (preg_match('/time=([0-9.]*) ms\n/',$lines,$matches))
		{
			$GLOBALS[ "pingbad" ] = 0;
			
			return intval($matches[ 1 ]);
		}
	}
	
	$GLOBALS[ "pingbad" ]++;
	
	return -1;
}

function SudoPing($host,$timeout = 100,$quiet = true) 
{	
	if (! isset($GLOBALS[ "sudo" ])) return -1;

	$time  = -1;
	$again =  3;
	
	while ($again > 0)
	{
		if (isset($GLOBALS[ "sudosocket" ]))
		{
			$socket = $GLOBALS[ "sudosocket" ];
		}
		else
		{
			$socket = @socket_create(AF_INET,SOCK_RAW,1);
		}
	
		$sec  = floor($timeout / 1000);
		$usec = ($timeout % 1000) * 1000;

		socket_set_option($socket,SOL_SOCKET,SO_RCVTIMEO,array("sec" => $sec, "usec" => $usec));
		
		if (socket_connect($socket,$host,null) === false)
		{
			if (! $quiet) echo "Cannot resolve '$host'.\n";
		}
		else
		{
			$type       = "\x08";
			$code       = "\x00";
			$checksum   = "\x00\x00";
			$identifier = chr(mt_rand(0,255)) . chr(mt_rand(0,255));
			$seqnumber  = chr(mt_rand(0,255)) . chr(mt_rand(0,255));
			$data       = "ping:$host";

			if (strlen($data) % 2) $data .= "\x00";
			
			$package = $type . $code . $checksum . $identifier . $seqnumber . $data;
			
			$bit = unpack('n*',$package);
			$sum = array_sum($bit);
			while ($sum >> 16) $sum = ($sum >> 16) + ($sum & 0xffff);
			$checksum = pack('n*',~$sum);

			$package = $type . $code . $checksum . $identifier . $seqnumber . $data;
			
			$idntlen = strlen($data);

			list($start_usec,$start_sec) = explode(" ",microtime());
			$start_time = ((float) $start_usec + (float) $start_sec);
		
			@socket_send($socket,$package,strlen($package),0);

			if ($res = @socket_read($socket,255)) 
			{
                $offset = strlen($res) - strlen($package);
                $pingidentifier = $res[ $offset + 4 ] . $res[ $offset + 5 ];
                $pingseqnumber  = $res[ $offset + 6 ] . $res[ $offset + 7 ];
				
				//if (substr($res,-$idntlen) == substr($package,-$idntlen))
	
				if (($pingidentifier == $identifier) && ($pingseqnumber == $seqnumber))
				{
					list($end_usec,$end_sec) = explode(" ",microtime());
					$end_time = ((float) $end_usec + (float) $end_sec);

					$total_time = $end_time - $start_time;

					$time = floor($total_time * 1000);
					if ($time <= 1) $time = -1;
					
					$again = 0;
				}
				else
				{
					if (strpos($res,"ping:") > 0)
					{
						echo "Ping: $host != " . substr($res,strpos($res,"ping:") + 5) . "...\n";
				
						while ($res = @socket_read($socket,255)) usleep(1000);
					
						$again--;
					}
					else
					{
						echo "Ping: unreachable $host...\n";
						
						$again = 0;
					}
				}
			}
			else
			{
				$again = 0;
			}
		}
	
		if (! isset($GLOBALS[ "sudosocket" ]))
		{
			socket_close($socket);
		}
   	}
   			
   	$GLOBALS[ "pingbad" ] = ($time == -1) ? $GLOBALS[ "pingbad" ] + 1 : 0;		

	return $time;
}

function GetAddrByHost($host,$timeout = 4) 
{	
	$query = `nslookup -timeout=$timeout -retry=2 $host`;
   
	if (preg_match('/\nAddress: (.*)\n/',$query,$matches))
	{
		$res = trim($matches[ 1 ]);
		
		//echo "GetAddrByHost: $host => $res\n";

		return $res;
	}
	
	//echo "GetAddrByHost: $host => nix\n";

	return false;
}

function WebPing($host,$timeout = 1000,$quiet = false) 
{ 
	if (! isset($GLOBALS[ "hostip" ])) $GLOBALS[ "hostip" ] = array();

	$timeout = 1 + floor(($timeout - 1) / 1000);
	
	$time = -1;
	
	for ($inx = 0; $inx < 2; $inx++)
	{
		if (! isset($GLOBALS[ "hostip" ][ $host ]))
		{
			$GLOBALS[ "hostip" ][ $host ] = GetAddrByHost($host);
		}
		
		$hostip = $GLOBALS[ "hostip" ][ $host ];

		if ($hostip !== false)
		{
			list($start_usec,$start_sec) = explode(" ",microtime());
			$start_time = ((float) $start_usec + (float) $start_sec);
  
			$socket = @fsockopen($hostip,80,$errno,$errstr,$timeout); 
	
			if (! $socket)
			{
				unset($GLOBALS[ "hostip" ][ $host ]);
				continue;
			}
			
			fclose($socket);
			
			list($end_usec,$end_sec) = explode(" ",microtime());
			$end_time = ((float) $end_usec + (float) $end_sec);

			$total_time = $end_time - $start_time;

			$time = floor($total_time * 1000);
			if ($time <= 1) $time = -1;
		
			if ($time != -1) break;
		}
		
		unset($GLOBALS[ "hostip" ][ $host ]);
	}

	return $time;
}

function MTR_GetHops($host)
{
	$mtr = "mtr -c 1 -r --no-dns " . $host;
	
	$pfd = popen($mtr,"r");

	$hops = Array();
	
	while (($line = fgets($pfd)) != null)
	{
		if (substr($line,0,5) == "HOST:") continue;
		
		$hop = explode(" ",trim($line));
		$hop = $hop[ 1 ];
		
		array_push($hops,$hop);
	}
		
	pclose($pfd);
	
	return $hops;
}

function MtrTask($task)
{
	$result = array();
	
	$result[ "what" ] = $task[ "what" ];
	$result[ "guid" ] = $task[ "guid" ];
	$result[ "list" ] = array();

	$mtrc  = isset($task[ "mtrc" ]) ? $task[ "mtrc" ] : 1;
	$mtrd  = isset($task[ "mtrd" ]) ? $task[ "mtrd" ] : 0;
	$ping  = isset($task[ "ping" ]) ? $task[ "ping" ] : 0;
	
	$diffs = array();
		
	if (isset($task[ "list" ]))
	{
		$todo = count($task[ "list" ]);
		
		foreach ($task[ "list" ] as $host)
		{
			Logdat("Mtr: list ($host/$mtrc/$mtrd)\n");

			$mtrrounds = array();
			
			for ($count = 0; $count < $mtrc; $count++)
			{
				if ($ping && (Ping($host) == -1)) break;
				
				$hops = MTR_GetHops($host);
				
				if ($mtrd > 0)
				{
					$last = array_pop($hops);
					$diffkey = implode(",",$hops);
					array_push($hops,$last);
					
					if (! isset($diffs[ $diffkey ]))
					{
						array_push($result[ "list" ],$hops);
						$diffs[ $diffkey ] = true;
					}
					
					if (count($diffs) >= $mtrd) break;
				}
				else
				{
					array_push($mtrrounds,$hops);
				}
				
				if (($mtrd > 0) && (count($diffs) >= $mtrd)) break;
			}
			
			if ($mtrd == 0) array_push($result[ "list" ],$mtrrounds);
			if (($mtrd > 0) && (count($diffs) >= $mtrd)) break;
		}
	}
	
	if (isset($task[ "from" ]) && isset($task[ "upto" ]))
	{
		$from = IP2Bin($task[ "from" ]);
		$upto = IP2Bin($task[ "upto" ]);
		
		$todo = $upto - $from;
		
		for ($ipbin = $from; $ipbin <= $upto; $ipbin++)
		{
			$ip = IPZero($ipbin);
			
			echo "Mtr: from ($ip/$mtrc/$mtrd)\n";

			$mtrrounds = array();
			
			for ($count = 0; $count < $mtrc; $count++)
			{
				if ($ping && (Ping(IP($ip)) == -1)) break;
				
				$hops = MTR_GetHops(IP($ip));
				
				if ($mtrd > 0)
				{
					$last = array_pop($hops);
					$diffkey = implode(",",$hops);
					array_push($hops,$last);
					
					if (! isset($diffs[ $diffkey ]))
					{
						array_push($result[ "list" ],$hops);
						$diffs[ $diffkey ] = true;
					}
					
					if (count($diffs) >= $mtrd) break;
				}
				else
				{
					array_push($mtrrounds,$hops);
				}
				
				if (($mtrd > 0) && (count($diffs) >= $mtrd)) break;
			}
			
			if ($mtrd == 0) array_push($result[ "list" ],$mtrrounds);
			if (($mtrd > 0) && (count($diffs) >= $mtrd)) break;
		}
	}
	
	return $result;
}

function CheckLine($force = false)
{
	if (($GLOBALS[ "pingbad" ] > 20) || $force)
	{
		if ((UserPing("www.bing.com",  2000) == -1) &&
			(UserPing("www.google.de", 2000) == -1) &&
			(UserPing("www.google.com",2000) == -1))
		{
			$GLOBALS[ "linebad" ] = true;
	
			echo "Line: offline, aborting task...\n";
		
			return false;
		}
		else
		{
			echo "Line: check success...\n";
		}
	
		$GLOBALS[ "pingbad" ] = 0;
	}
	
	return true;
}

function CheckTask($task)
{
	if (! isset($task[ "test" ])) return true;
	
	foreach ($task[ "test" ] as $test)
	{
		if (UserPing($test,1000) != -1) return true;
	}
	
	echo "Test: ($test) offline, aborting task...\n";
	
	return false;
}

function MtrPingJob($task,$ip,$mtrs)
{
	if (strlen($mtrs) == 0) return -1;

	$ms = -1;
	
	$mtrs = explode(",",$mtrs);
	
	foreach ($mtrs as $mtrdom)
	{
		$mtr = "mtr -c 1 -r --no-dns " . $mtrdom;
	
		$pfd = popen($mtr,"r");

		$hops = Array();
	
		while (($line = fgets($pfd)) != null)
		{
			if (substr($line,0,5) == "HOST:") continue;
		
			$line = trim($line);
			
			$line = str_replace("       "," ",$line);
			$line = str_replace("      "," ",$line);
			$line = str_replace("     "," ",$line);
			$line = str_replace("    "," ",$line);
			$line = str_replace("   "," ",$line);
			$line = str_replace("  "," ",$line);
			
			$hop = explode(" ",$line);
			
			$hopip = IPZero($hop[ 1 ]);
			
			if ($hopip == $ip)
			{
				$ms = floor(floatval($hop[ 4 ]));
				
				echo $task[ "what" ] . ": mtrpng " . IPZero($ip) . " = $ms ($mtrdom)\n";

				break;
			}
		}
		
		pclose($pfd);
		
		if ($ms != -1) break;
			
		echo $task[ "what" ] . ": mtrpng " . IPZero($ip) . " = -1 ($mtrdom)\n";
	}
	
	return $ms;
}

function WebPingTask($task)
{
	if (! CheckTask($task)) return null;

	$result = array();
	
	$result[ "what" ] = $task[ "what" ];
	$result[ "guid" ] = $task[ "guid" ];
	$result[ "list" ] = array();
			
	if (isset($task[ "list" ]))
	{
		$what = $task[ "what" ];	
		$lcnt = count($task[ "list" ]);
		
		for ($linx = 0; $linx < $lcnt; $linx++)
		{
			$host = $task[ "list" ][ $linx ];
			
			if (substr($host,0,4) != "www.") $host = "www." . $host;
			
			$ms  = -1;
			$ms1 = "n.a.";
			$ms2 = "n.a.";
			$ms3 = "n.a.";
		
			if ($ms == -1) $ms = $ms1 = WebPing($host,1000);
			if ($ms == -1) $ms = $ms2 = WebPing($host,2000);
			if ($ms == -1) $ms = $ms3 = WebPing($host,3000);
			
			$hostip = isset($GLOBALS[ "hostip" ][ $host ]) ? $GLOBALS[ "hostip" ][ $host ] : "n.n.";
			
			if ($ms == -1)
			{
				echo "$what: failed " . $host . " = $hostip = $ms1 $ms2 $ms3\n";
			}
			else
			{
				echo "$what: pinged " . $host . " = $hostip = $ms\n";
			}
			
			array_push($result[ "list" ],$ms);
		}
	}
	
	if (! CheckTask($task)) return null;
	
	return $result;
}

function AnyPingTask($task)
{
	if (! CheckTask($task)) return null;

	$result = array();
	
	$result[ "what" ] = $task[ "what" ];
	$result[ "guid" ] = $task[ "guid" ];
	$result[ "list" ] = array();
			
	if (isset($task[ "list" ]))
	{
		$what = $task[ "what" ];	
		$lcnt = count($task[ "list" ]);
		
		for ($linx = 0; $linx < $lcnt; $linx++)
		{
			$ip = $task[ "list" ][ $linx ];

			$ms  = -1;
			$ms1 = "n.a.";
			$ms2 = "n.a.";
			$ms3 = "n.a.";
		
			if ($ms == -1) $ms = $ms1 = Ping(IP($ip),500);
			if ($ms == -1) $ms = $ms2 = SudoPing(IP($ip),1000);
			if ($ms == -1) $ms = $ms3 = UserPing(IP($ip),2000);
			
			if (($ms == -1) && isset($task[ "pmtr" ]) && isset($task[ "pmtr" ][ $ip ]))
			{
				$ms = MtrPingJob($task,$ip,$task[ "pmtr" ][ $ip ]);
				
				echo "$what: mtrpng " . IPZero($ip) . " = $ms\n";
			}
			else
			{
				if ($ms == -1)
				{
					echo "$what: failed " . IPZero($ip) . " = $ms1 $ms2 $ms3\n";
				}
				else
				{
					echo "$what: pinged " . IPZero($ip) . " = $ms\n";
				}
			}
			
			array_push($result[ "list" ],$ms);
		}
	}
	
	if (! CheckTask($task)) return null;
	
	return $result;
}

function EndPingTask($task)
{
	if (! CheckTask($task)) return null;
	
	$result = array();
	
	$result[ "what" ] = $task[ "what" ];
	$result[ "guid" ] = $task[ "guid" ];
	$result[ "list" ] = array();
	$result[ "best" ] = array();
	
	if (isset($task[ "list" ]))
	{
		$todo = count($task[ "list" ]);
		$maxp = isset($task[ "maxp" ]) ? $task[ "maxp" ] : 128;
		
		$lcnt = count($task[ "list" ]);
		
		for ($linx = 0; $linx < $lcnt; $linx++)
		{
			$ip   = $task[ "list" ][ $linx ];
			$best = $task[ "best" ][ $linx ];

			echo "endping: " . IPZero($ip) . "\n";
			
			$ms   = -1;
			$bhit = "+";
		 
			if ($best !== false) 
			{
				$ms = Ping($best);
				
				if ($ms == -1) $ms = SudoPing($best,1000);
				if ($ms == -1) $ms = UserPing($best,1000);
			}
			
			if ($ms == -1)
			{
				$bhit   = "-";			
				$from   = IP2Bin($ip);
				$upto   = $from + $maxp;
				$maxtry = $upto - $from;
				
				$pingip = ($best === false) ? $from : IP2Bin($best);
				
				while ($maxtry-- > 0)
				{
					$ms = Ping(Bin2IP($pingip));
					
					if ($ms != -1) 
					{
						$best = Bin2IP($pingip);
						break;
					}
					
					if (++$pingip >= $upto) $pingip = $from;
					
					if (! CheckLine()) return null;
				}
			}

			array_push($result[ "list" ],$ms);
			array_push($result[ "best" ],$best);
			
			if ($best !== false)
			{
				echo "endping: " 
				   . IPZero($best) 
				   . "$bhit = $ms\n"
				   ;
			}
			else
			{
				echo "endping: " 
				   . IPZero($ip) 
				   . "$bhit = $ms\n"
				   ;
			}
		}
	}
	
	if (! CheckTask($task)) return null;
	
	return $result;
}

function NetPingTask($task)
{
	if (! CheckTask($task)) return null;

	$result = array();
	
	$result[ "what" ] = $task[ "what" ];
	$result[ "guid" ] = $task[ "guid" ];
	$result[ "list" ] = array();
	
	if (isset($task[ "list" ]))
	{
		$todo = count($task[ "list" ]);
		
		foreach ($task[ "list" ] as $ip)
		{
			$ms = Ping($ip);
			array_push($result[ "list" ],$ms);
			
			echo "netping: " . IPZero($ip) . " => $ms\n";

			if (! CheckLine()) return null;
		}
	}
	
	if (isset($task[ "from" ]) && isset($task[ "upto" ]))
	{
		$from = IP2Bin($task[ "from" ]);
		$upto = IP2Bin($task[ "upto" ]);
		$pcnt = $upto - $from;
		
		echo "netping: " . IPZero($from) . "/" . $pcnt . " start...\n";
		
		for ($binip = $from; $binip <= $upto; $binip++)
		{
			$ms = Ping(Bin2IP($binip));
			
			array_push($result[ "list" ],$ms);

			if (! CheckLine()) return null;
		}
		
		echo "netping: " . IPZero($from) . "/" .  $pcnt . " done...\n";
	}
	
	if (! CheckTask($task)) return null;

	return $result;
}

function CheckMtr(&$tasks)
{
	exec("which which",$lines,$return);
	if ($return != 0) return false;
	
	exec("which mtr",$lines,$return);
	if ($return != 0) return false;
	
	array_push($tasks,"mtr");
	
	return true;
}

function CheckPing(&$tasks)
{
	exec("which which",$lines,$return);
	if ($return != 0) return false;
	
	exec("which ping",$lines,$return);
	if ($return != 0) return false;
	
	array_push($tasks,"ping");
	
	array_push($tasks,"netping");
	array_push($tasks,"endping");
	array_push($tasks,"bblping");
	array_push($tasks,"uplping");
	array_push($tasks,"eplping");
	array_push($tasks,"gwyping");

	return true;
}

function CheckNSLookup(&$tasks)
{
	exec("which which",$lines,$return);
	if ($return != 0) return false;
	
	exec("which nslookup",$lines,$return);
	if ($return != 0) return false;
	
	array_push($tasks,"webping");

	return true;
}

function CheckSudo(&$tasks)
{
	//
    // Try to create a priveleged raw icmp socket.
    //
	
	$socket = @socket_create(AF_INET,SOCK_RAW,1);
	
    if ($socket === false) return false;
    
    if ($GLOBALS[ "uname" ] == "Darwin")
    {
    	//
    	// Darwin cannot re-use socket.
    	//
    	
    	socket_close($socket);
    }
    else
    {
    	//
    	// Store socket for further use.
    	//
        
        socket_close($socket);
	
    	//$GLOBALS[ "sudosocket" ] = $socket;
    }
    
	$GLOBALS[ "sudo" ] = true;
	
	array_push($tasks,"sudoping");
	
	return true;
}

function MainLoop($server_host,$server_port)
{
    //
    // Prepare a hello message with our capabilities.
    //
    
    $hello = array();
    
    $hello[ "what"    ] = "hello";
    $hello[ "host"    ] = $GLOBALS[ "hostname" ];
    $hello[ "version" ] = "1.04";
    $hello[ "tasks"   ] = array();
	
	//
	// Add capabilities we have.
	//
	
	if (CheckMtr     ($hello[ "tasks" ])) echo "Have mtr...\n";
	if (CheckPing    ($hello[ "tasks" ])) echo "Have ping...\n";
	if (CheckNSLookup($hello[ "tasks" ])) echo "Have nslookup...\n";
	if (CheckSudo    ($hello[ "tasks" ])) echo "Have sudo...\n";

	$hellopacket = EncodeMessage($hello);
	$sorrysleep  = 2;
	
	//
	// Open a generic UPD socket.
	//
	
	$socket = socket_create(AF_INET,SOCK_DGRAM,SOL_UDP);
	
    while (true)
    {
    	//
    	// Send hello message to server to indicate we are ready.
    	//
    	
   	 	socket_sendto($socket,$hellopacket,strlen($hellopacket),0,$server_host,$server_port);
   	 	
   	 	for ($try = 0; $try < 1000; $try++)
   	 	{
        	$xlen = @socket_recvfrom($socket,$xfer,8192,MSG_DONTWAIT,$remote_host,$remote_port);
        
        	if ($xlen !== false) break;
        	
        	usleep(1000);
        }
		
		if (($xlen === false) || ($xlen < 4))
		{
			//
			// We did not receive anything meaningfull,
			// so continue to send another hello.
			//
			
			echo "No response...\n";
			
        	sleep($sorrysleep);
        	
        	if ($sorrysleep >= 64) 
        	{
        		//
        		// Re-open another socket.
        		//
        		
        		socket_close($socket);
				
				$socket = socket_create(AF_INET,SOCK_DGRAM,SOL_UDP);
				
				$sorrysleep = 2;
        	}
        	else
        	{
        		$sorrysleep += 2;
        	}
        	
			continue;
		}
		
		//
		// We received a message.
		//
		
        $jlen = (ord($xfer[ 0 ]) << 24) + (ord($xfer[ 1 ]) << 16)
        	  + (ord($xfer[ 2 ]) <<  8) + (ord($xfer[ 3 ]) <<  0);
        
        $json = substr($xfer,4);

        $task = json_decode($json,true);
        
        if (! ($task && isset($task[ "what" ])))
        {
        	echo "Unknown message...\n";
        	sleep(10);
        	continue;
        }
        
        $GLOBALS[ "linebad" ] = false;
        $GLOBALS[ "pingbad" ] = 0;
        
        $result = null;
        
        switch ($task[ "what" ])
        {
        	//
        	// Server has nothing to do for us.
        	//
        	
        	case "sorry" :
        		echo "Sorry: " . $task[ "text" ] . "\n";
			
        		sleep($sorrysleep);
        		if ($sorrysleep < 64) $sorrysleep += 2;
        		
				break;
        	
        	//
        	// Ping tasks.
        	//
        	
        	case "netping" : $result = NetPingTask($task); $sorrysleep = 2; break;
        	case "endping" : $result = EndPingTask($task); $sorrysleep = 2; break;
        	case "eplping" : $result = AnyPingTask($task); $sorrysleep = 2; break;
        	case "gwyping" : $result = AnyPingTask($task); $sorrysleep = 2; break;
        	case "bblping" : $result = AnyPingTask($task); $sorrysleep = 2; break;
        	case "uplping" : $result = AnyPingTask($task); $sorrysleep = 2; break;
        	case "webping" : $result = WebPingTask($task); $sorrysleep = 2; break;
        	        	
        	//
        	// Mtr task.
        	//
        	
        	case "mtr" :
        		$result = MtrTask($task);
        		$sorrysleep = 2;
        		break;
        	        	
        	//
        	// Unknown task.
        	//
        		
         	default :
         		echo "Unknown task => " . $task[ "what" ] . "\n";
        		sleep(60);
				break;
		}
        
        if ($result && ! $GLOBALS[ "linebad" ])
        {
        	//
        	// Encode results and send them back.
        	//
        	
        	$message = EncodeMessage($result);
   	 		socket_sendto($socket,$message,strlen($message),0,$server_host,$server_port);
         	sleep(1);
  	 	}
	}
}

//
// Shutdown signal handler.
//

function Shutdown($signo)
{
	$GLOBALS[ "shutdown" ] = true;
	
	Logdat("Received shutdown signal...\n");
}

//
// Fork number of processes and start read loop.
//

function ForkProcs($selfname,$numprocs)
{
	declare(ticks = 1);
	
	$GLOBALS[ "shutdown" ] = false;
	
	if (function_exists("pcntl_signal"))
	{
		pcntl_signal(SIGTERM,"Shutdown");
		pcntl_signal(SIGHUP, "Shutdown");
		pcntl_signal(SIGUSR1,"Shutdown");
	}
	
	if (! is_dir("../run")) mkdir("../run",0755);
	if (! is_dir("../log")) mkdir("../log",0755);
	
	file_put_contents("../run/$selfname.pid",getmypid());
	
	$procs = array();
	$pipes = array();
	$pspec = array(1 => array("pipe","w"));
	
	for ($inx = 0; $inx < $numprocs; $inx++)
	{
		$pipe = array();
		$proc = proc_open("php $selfname",$pspec,$pipe);
		
		stream_set_blocking($pipe[ 1 ],false);
		
		array_push($procs,$proc);
		array_push($pipes,$pipe);
	}
	
	while (! $GLOBALS[ "shutdown" ])
	{			
		usleep(100000);

		for ($inx = 0; $inx < $numprocs; $inx++)
		{
			$line = fgets($pipes[ $inx ][ 1 ]);
			
			if ($line === false) continue;
			
			Logdat(str_pad($inx,2,"0",STR_PAD_LEFT) . ":" . $line);
		}
		
		Logflush();
	}
	
	Logdat("Shutdown all clients...\n");

	for ($inx = 0; $inx < $numprocs; $inx++)
	{
		proc_terminate($procs[ $inx ]);
	}
	
	Logdat("Shutdown all clients done.\n");
	Logdat("Exitting.\n");
	
	exit(0);
}

function Main()
{
	date_default_timezone_set("UTC");

	if (count($_SERVER[ "argv" ]) > 1)
	{
		$selfname = $_SERVER[ "argv" ][ 0 ];
		$numprocs = intval($_SERVER[ "argv" ][ 1 ]);
	
		ForkProcs($selfname,$numprocs);
	}
	else
	{
		MainLoop($GLOBALS[ "server_host" ],$GLOBALS[ "server_port" ]);
	}
}

Main();
?>
