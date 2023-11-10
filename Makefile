EXE=dhcp-stats
LOGIN=xvrabl05
FILES_TO_PACK= $(EXE).cpp $(EXE).h Makefile manual.pdf dhcp-stats.1
FLAGS=-lncurses -lpcap
main: $(EXE).cpp 
	g++ $(EXE).cpp -o $(EXE) $(FLAGS)

tar: $(FILES_TO_PACK)
	tar -cvf $(LOGIN).tar $(FILES_TO_PACK)

clean:
	rm -f $(EXE)

run: clean main
	./$(EXE) $(PARAM)


