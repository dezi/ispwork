<?php

$GLOBALS[ "uname" ] = trim(`uname`);

$GLOBALS[ "server_host" ] = "xberry.org";
$GLOBALS[ "server_port" ] = 11042;

function Logdat($message)
{
	if (! isset($GLOBALS[ "logfd" ]))
	{
		$GLOBALS[ "logfd" ] = fopen("../log/taskclient.log","a");
	}
	
	fputs ($GLOBALS[ "logfd" ],$message);
	fflush($GLOBALS[ "logfd" ]);
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

function Ping($host)
{
	if (isset($GLOBALS[ "socket" ]))
	{
		return SudoPing($host);
	}
	
	return UserPing($host);
}

function UserPing($host)
{
	if ($GLOBALS[ "uname" ] == "Darwin")
	{
		exec("ping -c 1 -t 1 $host",$lines,$return);
	}
	else
	{
		exec("ping -c 1 -W 1 $host",$lines,$return);
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
	$time = -1;

   	if ($GLOBALS[ "uname" ] == "Darwin")
	{
		//
		// Darwin/OSX cannot re-connect socket. Create new.
		//
		
		$socket = @socket_create(AF_INET,SOCK_RAW,1);
		
		$timeout = 100;
		$sec  = floor($timeout / 1000);
		$usec = ($timeout % 1000) * 1000;
	
		socket_set_option($socket,SOL_SOCKET,SO_RCVTIMEO,array("sec" => $sec, "usec" => $usec));
	}
	else
	{
		$socket = $GLOBALS[ "socket" ];
	}
	
	if (@socket_connect($socket,$host,null) === false)
	{
		if (! $quiet) echo "Cannot resolve '$host'.\n";
	}
	else
	{
		list($start_usec,$start_sec) = explode(" ",microtime());
		$start_time = ((float) $start_usec + (float) $start_sec);

		$package = "\x08\x00\x19\x2f\x00\x00\x00\x00\x70\x69\x6e\x67";
		socket_send($socket,$package,strlen($package),0);

		if (@socket_read($socket,255)) 
		{
			list($end_usec,$end_sec) = explode(" ",microtime());
			$end_time = ((float) $end_usec + (float) $end_sec);

			$total_time = $end_time - $start_time;

			$time = floor($total_time * 1000);
			if ($time <= 1) $time = -1;
		} 
	}
	
   	if ($GLOBALS[ "uname" ] == "Darwin")
   	{
		//
		// Darwin/OSX cannot re-connect socket. Close old.
		//
		
   		socket_close($socket);
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
			Log("Mtr: list ($host/$mtrc/$mtrd)\n");

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

function CheckLine()
{
	if ($GLOBALS[ "pingbad" ] > 5) 
	{
		if (Ping("www.google.com") == -1)
		{
			$GLOBALS[ "linebad" ] = true;
	
			echo "Line: offline, aborting task...\n";
		
			return false;
		}
	
		$GLOBALS[ "pingbad" ] = 0;
	}
	
	return true;
}

function EndpointPingTask($task)
{
	$result = array();
	
	$result[ "what" ] = $task[ "what" ];
	$result[ "guid" ] = $task[ "guid" ];
	$result[ "list" ] = array();
	$result[ "best" ] = array();
	
	if (isset($task[ "list" ]))
	{
		$todo = count($task[ "list" ]);
		$maxp = isset($task[ "maxp" ]) ? $task[ "maxp" ] : 128;
		
		echo "Endping: list ($todo) start...\n";
		
		foreach ($task[ "list" ] as $ip)
		{
						
			$from = IP2Bin($ip);
			$upto = $from + $maxp;
			$ms   = -1;
			
			$bhit = "-";
			$best = array_pop($task[ "best" ]);
			
			if ($best !== false) $ms = Ping($best);
			
			if ($ms != -1)
			{
				$bhit = "+";
			}
			else
			{
				$best = false;
				
				for ($pingip = $from; $pingip < $upto; $pingip++)
				{
					$ms = Ping(Bin2IP($pingip));
					
					if ($ms != -1) 
					{
						$best = Bin2IP($pingip);
						break;
					}
				}
			}

			array_push($result[ "list" ],$ms);
			array_push($result[ "best" ],$best);
			
			if ($best !== false)
			{
				/*
				echo "Endping: list (" 
				   . IPZero($best) 
				   . "$bhit) = $ms\n"
				   ;
				*/
			}
			else
			{
				echo "Endping: list (" 
				   . IPZero($ip) 
				   . "$bhit) = $ms\n"
				   ;
			}
		}
		
		echo "Endping: list ($todo) done.\n";
	}

	return $result;

}

function PingTask($task)
{
	$result = array();
	
	$result[ "what" ] = $task[ "what" ];
	$result[ "guid" ] = $task[ "guid" ];
	$result[ "list" ] = array();
	
	if (isset($task[ "list" ]))
	{
		$todo = count($task[ "list" ]);
		
		echo "Ping: list ($todo) start...\n";
		
		foreach ($task[ "list" ] as $ip)
		{
			$ms = Ping($ip);
			array_push($result[ "list" ],$ms);
			
			echo "Ping: " . IPZero($ip) . " => $ms\n";

			if (! CheckLine()) return null;
		}
		
		echo "Ping: list ($todo) done.\n";
	}
	
	if (isset($task[ "from" ]) && isset($task[ "upto" ]))
	{
		$from = IP2Bin($task[ "from" ]);
		$upto = IP2Bin($task[ "upto" ]);
		
		echo "Ping: from " . IPZero($from) . "\n";
		echo "Ping: upto " . IPZero($upto) . "\n";
		
		for ($binip = $from; $binip <= $upto; $binip++)
		{
			$ip = Bin2IP($binip);
			$ms = Ping($ip);
			
			array_push($result[ "list" ],$ms);
		}

		if (! CheckLine()) return null;
		
		echo "Ping: from " . IPZero($from) . " done.\n";
	}
	
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
	array_push($tasks,"endping");

	return true;
}

function CheckSudo(&$tasks)
{
	//
    // Try to create a priveleged raw icmp socket.
    //
	
	$socket = @socket_create(AF_INET,SOCK_RAW,1);
	
    if ($socket !== false)
    {
		$timeout = 100;
		$sec  = floor($timeout / 1000);
		$usec = ($timeout % 1000) * 1000;
	
		socket_set_option($socket,SOL_SOCKET,SO_RCVTIMEO,array("sec" => $sec, "usec" => $usec));
		
		array_push($tasks,"sudoping");
		
		$GLOBALS[ "socket" ] = $socket;
		
		return true;
	}
	
	return false;
}

function MainLoop($server_host,$server_port)
{
	//
	// Open a generic UPD socket.
	//
	
	$socket = socket_create(AF_INET,SOCK_DGRAM,SOL_UDP);
    
    //
    // Prepare a hello message with our capabilities.
    //
    
    $hello = array();
    
    $hello[ "what"    ] = "hello";
    $hello[ "version" ] = "1.0";
    $hello[ "tasks"   ] = array();
	
	//
	// Add capabilities we have.
	//
	
	if (CheckMtr ($hello[ "tasks" ])) echo "Have mtr...\n";
	if (CheckPing($hello[ "tasks" ])) echo "Have ping...\n";
	if (CheckSudo($hello[ "tasks" ])) echo "Have sudo...\n";

	$hellopacket = EncodeMessage($hello);
	$sorrysleep  = 2;
	
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
        	if ($sorrysleep < 64) $sorrysleep += 2;
        	
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
        	// Ping task.
        	//
        	
        	case "ping" :
        		$result = PingTask($task);
        		$sorrysleep = 2;
        		break;
        	        	
        	//
        	// Endpoint ping task.
        	//
        	
        	case "endping" :
        		$result = EndpointPingTask($task);
        		$sorrysleep = 2;
        		break;
        	        	
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
         		echo "Unknown task => " . $task[ "task" ] . "\n";
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
		usleep(25);

		for ($inx = 0; $inx < $numprocs; $inx++)
		{
			$line = fgets($pipes[ $inx ][ 1 ]);
			
			if ($line !== false) Logdat(str_pad($inx,2,"0",STR_PAD_LEFT) . ":" . $line);
		}
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