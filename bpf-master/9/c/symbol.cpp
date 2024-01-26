class Class {
	public:
 		int function() {
			return 0;
 		}
};

int defaultFunction() {
	Class *c = new Class();
	c->function();
	return 0;
}

extern "C" int externedFunction() {
	return 0;
}
