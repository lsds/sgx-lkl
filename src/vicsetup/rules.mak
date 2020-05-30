OBJECTS = $(SOURCES:.c=.o)

ifdef PROGRAM
$(PROGRAM): dirs $(OBJECTS)
	gcc -o $(PROGRAM) $(CFLAGS) $(OBJECTS) $(LDFLAGS)
endif

ifdef ARCHIVE
$(ARCHIVE): $(OBJECTS)
	ar rv $(ARCHIVE) $(OBJECTS)
endif

%.o: %.c
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(OBJECTS) $(PROGRAM) $(ARCHIVE) $(CLEAN) depend.mak

depend:
	@ rm -f depend.mak
	@ $(foreach i, $(SOURCES), gcc -M -MG $(DEFINES) $(INCLUDES) $(i) -MT $(i:.c=.o) >> depend.mak $(NL) )

ifdef DIRS
dirs:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )
else
dirs:
endif
