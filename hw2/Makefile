all:
	g++ -o logger.so -shared -fPIC inject.cpp -ldl
	g++ -o logger -Wall -g hw2.cpp

clean:
	rm -f logger
	rm -f logger.so
