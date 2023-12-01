<?php
function myend($value) {
	if($value>0) {
		echo($value . "\n") ;
		return myend($value-1) ;
	}
	echo("end\n");
	return $value;
}

function mystart($value) {
	while(True) {
		echo("start\n");
		myend($value);
		sleep(1);
	}
}

mystart(3);
?>
