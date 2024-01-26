test:
	while true; do curl localhost:1234; sleep 1; done

writer:
	./obj_pin_writer.py

reader:
	./obj_pin_reader.py

clean:
	rm -f /sys/fs/bpf/counter
