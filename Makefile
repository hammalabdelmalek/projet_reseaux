prog: app app2

app: app.c
	gcc app.c -o  app -lssl -lcrypto

app2: app2.c 
	gcc app2.c -o  app2 -lssl -lcrypto 

