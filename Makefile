flowmon : flowmon.c
	gcc -o flowmon flowmon.c
	chmod +x flowmon

clean :
	rm flowmon
