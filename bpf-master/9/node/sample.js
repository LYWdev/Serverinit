const sleep = function(seconds) {
	return new Promise((resolve) => {
		setTimeout(resolve, seconds*1000);
	});
}
const log = function(msg) { 
	process.stdout.write(msg + '\n');
}

function end(value) {
	if (value > 0) {
		log(value) ;
		return end(value-1) ;
	}
	log("end") ;
	return value ;
}

async function start(value) {
	log("start") ;
	while (true) {
		end(value) ;
		await sleep(1) ;
	}
	return value ;
}

start(3) ;
