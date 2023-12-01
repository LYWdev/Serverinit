class Sample
	def _end(value)
		if value > 0
			puts(value)
			return _end(value-1)
		end
		puts("end")
		return value
	end

	def _start(value)
		puts("start")
		while true
			_end(value)
			sleep(1)
		end
	end
end

sample = Sample.new()
sample._start(3)
