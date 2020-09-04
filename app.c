#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include<arpa/inet.h>
#include<time.h>
#include <openssl/sha.h>
#include <netdb.h>

#define reqlen 1024




typedef struct voisins{
   char hostadresse[INET6_ADDRSTRLEN];
   char port[5];
  int type;//1 permannent 0 sinon 
  time_t date;

}voisins;

typedef struct listevois listevois;
struct listevois
{
    voisins data;
    listevois  *suivant;
};



typedef struct donnees {
	 unsigned char i[8];
	 unsigned char s[2];
         char d[192];
	
}donnees;

typedef struct listeDonnees listeDonnees;
struct listeDonnees
{
    donnees data;
    listeDonnees  *suivant;
};

void afficher(listeDonnees *l){
listeDonnees *q = l;
while(q!=NULL){
printf("l'id :  ");
for(int n=0;n<8;n++){
	printf("%02x",q->data.i[n]);		
} 
printf("  et le seqno :  ");
for(int n=0;n<2;n++){
	printf("%02x",q->data.s[n]);		
}
printf("  et le data : %s\n",q->data.d);
q=q->suivant;
}


}

int compare(uint16_t *seqno1, uint16_t *seqno2){
	uint16_t sous=ntohs(*seqno1)-ntohs(*seqno2);
	if((sous&32768)==0){
		return 1;
	}else{
		return 0;
	}
	
}


void add_vois(listevois *l ,char *addr,int (*nbr_vois),int type){

    listevois *q = l;
    listevois *new_d=malloc(sizeof(listevois));
    memcpy(new_d->data.hostadresse,addr,strlen(addr));
    memcpy(new_d->data.port,"13579",5);
    new_d->data.date=time(NULL);
    new_d->data.type=type;		
    new_d->suivant=NULL;
    if(*nbr_vois==0){
    memcpy(l->data.hostadresse,addr,strlen(addr));
    memcpy(l->data.port,"13579",5);
    l->data.date=time(NULL);
    l->data.type=type;		
    l->suivant=NULL;
   }else{	
    while(q->suivant!=NULL)
    {
    q=q->suivant;
    }

    q->suivant=new_d;

   }
   
    (*nbr_vois)=(*nbr_vois)+1;	    
}

void affiche_vois(listevois *l,int *nbr_vois){
	
  listevois *q = l;
  for(int i=0;i<*nbr_vois;i++){
	printf("date : %s ",asctime(gmtime(&q->data.date)));
	printf("l'adresse %s\n",q->data.hostadresse);
	q=q->suivant;
  }


}


int exist_vois(listevois *l,char *addr){
	
  listevois *q = l;
  while(q!=NULL){
	if(strcmp(q->data.hostadresse,addr)==0){
	   return 1;	
	}
	q=q->suivant;
  }	
  return 0;
}

void update(listevois *l,char *addr){

  listevois *q = l;

  while(q!=NULL){
	if(strcmp(q->data.hostadresse,addr)==0){
	   q->data.date=time(NULL);
	}
	q=q->suivant;
  }	
  

}

void ajout_donnees(listeDonnees *l,unsigned char *id,uint16_t * seqno,unsigned char *data ,int *nbr_donnee){
     listeDonnees *q = l;
     listeDonnees *new_d=malloc(sizeof(listeDonnees));
     memcpy(new_d->data.i,id,8);
     memcpy(new_d->data.s,seqno,8);
     memcpy(new_d->data.d,data,strlen((const char *)data));
    while(q->suivant!=NULL){
    	q=q->suivant;
    }

    q->suivant=new_d;
   
    (*nbr_donnee)=(*nbr_donnee)+1;
     	

}

void modifier_madonnee(listeDonnees *l , donnees d){
  
   l->data=d;

}

void modifier_monseqno(listeDonnees *l){

uint16_t s;
memcpy(&s,l->data.s,2);
s=ntohs(s);
s=(s+1)&65535;
s=htons(s);
memcpy(l->data.s,&s,2);

}


void miseajour_vois(listevois *v, int *nbr_vois){
	listevois *q=v,*suiv=NULL,*p;
	if(q!=NULL){
          suiv=q->suivant;
	  if(time(NULL)-q->data.date >=70 && q->data.type==0){
          	v=v->suivant;
		free(q);       
	  }
        }
	while(suiv!=NULL){
		if(time(NULL)-suiv->data.date >=70 && suiv->data.type==0){
                 p=suiv;
		 q->suivant=suiv->suivant;
		 free(p);
		 (*nbr_vois)--;
	        }
		q=q->suivant;
		suiv=suiv->suivant;
	}

}



unsigned char* nodeHash(donnees *d){


unsigned char concat[strlen((const char *)d->d)+10];
memset(concat,0,strlen(d->d)+10);
memcpy(&concat[0],&d->i,8);
memcpy(&concat[8],&d->s,2);
memcpy(&concat[10],&d->d,strlen((const char *)d->d));
	


int taille = strlen((const char *)d->d)+10;
  
unsigned char *k = SHA256(concat,taille, 0);
unsigned char *b=malloc(16);
memcpy(b,k,16);

return b;
		
}

void nodehash(unsigned char *sortie,donnees *d){
int taille = strlen((const char *)d->d)+10;
unsigned char concat[taille];
memset(concat,0,strlen(d->d)+10);
memcpy(&concat[0],&d->i,8);
memcpy(&concat[8],&d->s,2);
memcpy(&concat[10],&d->d,taille-10);
	
unsigned char *k = SHA256(concat,taille, 0);

memcpy(sortie,k,16);
}

listeDonnees *trouve(listeDonnees *l,unsigned char *id){
        listeDonnees *q=l; 
	while(q!=NULL){
		if(memcmp(q->data.i,id,8)==0){
			return q;	
		}
	  q=q->suivant;
	}
	return NULL;

}



unsigned char* networkHash(listeDonnees *l,int numberdonnee)
{
        unsigned char h[numberdonnee*16],m[16]; 
	memset(h,0,numberdonnee*16);
	memset(m,0,16);
        listeDonnees *q;
        int i=0;
        for(q=l;q!=NULL;q=q->suivant){
	nodehash(m,&q->data);
        memcpy(&h[i],m,16);
        i=i+16;   
        }
   
   int taille =numberdonnee*16;    
   unsigned char *k = SHA256(h,taille, 0);
   unsigned char *b=malloc(16*sizeof(char));
   memcpy(b,k,16);

   return b; 			
				

}

void networkhash(unsigned char *retour,listeDonnees *l,int numberdonnee){

        unsigned char h[numberdonnee*16],m[16]; 
	memset(h,0,numberdonnee*16);
	memset(m,0,16);
        listeDonnees *q;
        int i=0;
        for(q=l;q!=NULL;q=q->suivant){
	nodehash(m,&q->data);
        memcpy(&h[i],m,16);
        i=i+16;   
        }
   
        int taille =numberdonnee*16;    
        unsigned char *k = SHA256(h,taille, 0);
        memcpy(retour,k,16);

}

void entet(unsigned char *paquet,uint16_t taille){
uint16_t h=htons(taille);
paquet[0]=95;
paquet[1]=1; 
memcpy(&paquet[2],&h,2);
}

int test_paquet(unsigned char *p){
 uint16_t taille_paquet;
 memcpy(&taille_paquet,&p[2],2);
 taille_paquet=ntohs(taille_paquet);
 if(taille_paquet >1020){
	return 0;
 }

 if(p[0]!=95 || p[1]!=1 || (p[2]==0 && p[3]==0)){
 	return 0;
  }
  
 else {
	return 1;
  }

}

int test_tlv(unsigned char *t){
 uint8_t taille_tlv=t[1];

  if(t[0]==2){
	if(taille_tlv !=0){
		return 0;
	}
 }

 if(t[0]==3){
	if(taille_tlv !=18){
		return 0;
	}
 }

 if(t[0]==4){
	if(taille_tlv !=16){
		return 0;
	}
 }

  if(t[0]==5){
	if(taille_tlv !=0){
		return 0;
	}
 }

   if(t[0]==6){
	if(taille_tlv !=26){
		return 0;
	}
 }

   if(t[0]==7){
	if(taille_tlv !=8){
		return 0;
	}
 }

    if(t[0]==8){
	if(taille_tlv <26 || taille_tlv > 218){
		return 0;
	}
 }

  return 1;	

}

void neighbouRequest(unsigned char *paquet)
{
paquet[0]=2;
paquet[1]=0;
}

void neigHBour(unsigned char *paquet , voisins *v)
{
paquet[0]=3;
paquet[1]=18;
memcpy(&paquet[2],&v->hostadresse,16);
memcpy(&paquet[18],&v->port,2);
}

void netHash(unsigned char *paquet , listeDonnees *l,int numberdonnee)
{
paquet[0]=4;
paquet[1]=16;
unsigned char hash[16];
networkhash(hash,l,numberdonnee);
memcpy(&paquet[2],hash,16);
}

void network_state_request(unsigned char *paquet)
{
paquet[0]=5;
paquet[1]=0;
}

void send_node_hash(unsigned char *paquet ,donnees* d)
{
paquet[0]=6;
paquet[1]=26;
memcpy(&paquet[2],&d->i,8);
memcpy(&paquet[10],&d->s,2);
unsigned char hash[16];
nodehash(hash,d);
memcpy(&paquet[12],hash,16);
}

void node_state_request(unsigned char *paquet , unsigned char id[8])
{
paquet[0]=7;
paquet[1]=8;
memcpy(&paquet[2],id,8);
}

void NodeState(unsigned char *paquet, donnees* d)
{

uint16_t tmp = strlen((const char *)d->d) + 28;
uint16_t taille_donnee = htons(tmp);
uint8_t tmp2 = strlen((const char *)d->d) + 26;
unsigned char hash[16];
nodehash(hash,d);

paquet[0]=95;
paquet[1]=1;
memcpy(&paquet[2],&taille_donnee,2);
paquet[4]=8;
memcpy(&paquet[5],&tmp2,1);
memcpy(&paquet[6],&d->i,8);
memcpy(&paquet[14],&d->s,2);
memcpy(&paquet[16],hash,16);
memcpy(&paquet[32],d->d,strlen((const char *)d->d));
}

void warning(unsigned char *paquet,char *message){

uint16_t tmp = strlen((const char *)message) + 2;
uint16_t taille_donnee = htons(tmp);
paquet[0]=95;
paquet[1]=1;
memcpy(&paquet[2],&taille_donnee,2);
paquet[4]=9;
paquet[5]=tmp-2;
memcpy(&paquet[6],message,tmp-2);
	
}


int main(){

  struct addrinfo hints, *res, *p;
  void *addr;
  int status,j,s,val,rc,l,i;
  char ipstr[INET6_ADDRSTRLEN];
  char mapiv4[20];
  memset(mapiv4,0,20);
  memset(ipstr,0,INET6_ADDRSTRLEN);	
 
  int nbr_v=0;//nbr de voisins  intialisé à 0 
  int nbr_donnee=1;//nbr de données intialisé à 1
  uint64_t  id=7999876539996846;//mon id
  uint16_t seqno=0;//mon seqno
  char madonnee[192];//ma donnée
  listeDonnees *ld=malloc(sizeof(listeDonnees));//ma liste de donnée
  donnees d;//ma donnée
  listevois *lv=malloc(sizeof(listevois));;
  

  //copie mon id et seqno dans ma structure de donnée 
  uint16_t o=htons(id);
  memcpy(&d.i,&o,8);
  uint16_t c=htons(seqno);
  memcpy(&d.s,&c,2);
  memset(d.d,0,192);

  ld->data=d;
  ld->suivant=NULL;	

  //utilisation de getaddrinfo
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // IPv4 ou IPv6
  hints.ai_socktype = SOCK_DGRAM; // Une seule famille de socket UDP

  if ((status = getaddrinfo("vps-63c87489.vps.ovh.ne", NULL, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    return 2;
  }
  
  p = res;


  while (p != NULL) {

    // Identification de l'adresse courante
    if (p->ai_family == AF_INET) { // IPv4
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
      addr = &(ipv4->sin_addr);

      // Conversion de l'adresse IP en une chaîne de caractères	
      inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
      memcpy(&mapiv4[0],"::ffff:",7);
      strcat(mapiv4,ipstr);
      printf("ipv4 = %s\n",mapiv4);	
      add_vois(lv,mapiv4,&nbr_v,1);		
    }
    else { // IPv6
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
      addr = &(ipv6->sin6_addr);

      // Conversion de l'adresse IP en une chaîne de caractères	
      inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr); 
      printf("ipv6 = %s\n",ipstr);
      add_vois(lv ,ipstr,&nbr_v,1);	   
    }

    // Adresse suivante
    p = p->ai_next;
  }
 

  // Libération de la mémoire occupée par les enregistrements
  freeaddrinfo(res);	

  s = socket(AF_INET6, SOCK_DGRAM, 0);
  struct sockaddr_in6 server;
  memset(&server, 0, sizeof(server));
  server.sin6_family = AF_INET6;
  server.sin6_port = htons(13579);
	  
  // option : réutilisation du numéro de port
  val = 1;
  rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
 // option : socket polymorphe 
  val = 0;
  rc = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
	 
 /* liaison socket serveur a l'adresse */
 rc = bind(s, (struct sockaddr*)&server, sizeof(server));
 if(rc < 0){
   perror("bind");
   exit(EXIT_FAILURE);
 }

  

  //ma boucle	
  while(1){

	 printf("nombre de voisins egale a : %d\n",nbr_v);
	 printf("nombre de donnees egale a : %d\n",nbr_donnee);
	 


	//demender si l'utilisateur veut changer la donnée
  	printf("si vous voulez changer votre données taper 1 sinon autre\n");
        scanf("%d",&j);
        if(j==1){
		  printf("donner votre donnee\n");
  		  scanf("%s",madonnee);
                  seqno=(seqno+1)&65535;
                  printf("votre donnée a bien ete changé\n");
	          //copie mon seqno et ma donnée dans ma structure de donnée 
            	  uint16_t f=htons(seqno);	
           	  memcpy(&d.s,&f,2);
                  memmove(d.d,madonnee,strlen(madonnee));	
            	 
	 	  //modifier ma donnée dans ma liste	
            	  modifier_madonnee(ld,d); 

            }


        //configuration du select !!!
	fd_set rfds;
        struct timeval tv;
        int retval;

        /* attendre stdin (fd s) pour voire quand elle a d'entré. */
	FD_ZERO(&rfds);
        FD_SET(s, &rfds);

        /* attendre jusqu'a 20 seconds. */
        tv.tv_sec = 20;
        tv.tv_usec = 0;

	retval = select(s+1, &rfds, NULL, NULL, &tv);


	//testé la sorie du select         
        if (retval == -1){
               perror("select()");
	}else{
	      if (retval){

               printf("j'ai chopé une entré.\n");
	       unsigned char req[reqlen];
               struct sockaddr_in6 client;
               socklen_t client_len = sizeof(client);
               rc = recvfrom(s, req, reqlen, 0, &client, &client_len);

               if(rc < 0) {
			perror("recvfrom");	
			continue;
		}

               inet_ntop(client.sin6_family, &client.sin6_addr, ipstr, sizeof ipstr);

               printf("l'adresse recue egale a %s\n",ipstr);

		
		//tester le tete du paquet
	       if(test_paquet(req)==1){	
			printf("le paquet est juste\n");
		//passer au paquet seulement si le voisins existe ou bien il reste de la place pour l'ajouté
	       if(exist_vois(lv,ipstr)||nbr_v<15){
	
	           if(exist_vois(lv,ipstr)){
			printf("l'adresse existe dans la table des voisins\n");
			update(lv,ipstr);
	       	   }else{
			
			printf("l'adresse n'existe pas dans la table des voisins mais en va l'ajouté \n");
			add_vois(lv ,ipstr,&nbr_v,0);
		
			}
			
		        uint16_t taille_paquet;
                        memcpy(&taille_paquet,&req[2],2);
                        taille_paquet=ntohs(taille_paquet);
                        int point=4;
			uint16_t taille_accumele=4;
			
			while(taille_accumele<taille_paquet+4){
			
			if(test_tlv(&req[point])){
				printf("le test du tlv est juste\n");
			}else{
				printf("le test du tlv est faux\n");
				char *message="il y'a un tlv avec une taille incoherente";
				unsigned char repl[strlen(message)+6];
				warning(repl,message);
				l = inet_pton(AF_INET6,ipstr,&server.sin6_addr);
          			rc = sendto(s, repl,strlen(message)+6, 0,(struct sockaddr*)&server, sizeof(server));
  	  			if(rc<0){
   					perror("sendto");
          	 		}else{
				   printf("tlv warning a bien ete envoyez\n");	
				}
				break;	
			}
			
			printf("le tlv recue egale a :%d\n",req[point]);

			if(req[point]==0){
				taille_accumele=taille_accumele+1;
				point=point+1;
			}
			
			if(req[point]==1){
				uint8_t x=req[point+1];
				taille_accumele=taille_accumele+x+2;
				point=point+x+2;
			}


			if(req[point]==2){
				printf("tlv Neighbour request recue\n");
			        unsigned char repl[24];
                                entet(repl,20);
				int nbgen=rand()%nbr_v;
				listevois *vh=lv;
				for(i=0;i<nbgen;i++){
				   vh=vh->suivant;			
				}
                                neigHBour(&repl[4],&vh->data);
				//envoi d'un tlv nighbour
		
				l = inet_pton(AF_INET6,ipstr,&server.sin6_addr);
                                   
          			rc = sendto(s, repl,24, 0,(struct sockaddr*)&server, sizeof(server));
  	  			if(rc<0){
   					perror("sendto");
          	 		}else{
				   printf("tlv neighbor a bien ete envoyez\n");	
				}
				taille_accumele=taille_accumele+2;
				point=point+2;
                                
			}

			
			if(req[point]==3){
				printf("tlv Neighbour recue\n");
                                unsigned char ipaddr[16];
                                memcpy(ipaddr,&req[point+2],16);
				unsigned char repl[22];
               			entet(repl,18);
               			netHash(&repl[4],ld,nbr_donnee);
				l = inet_pton(AF_INET6,(const char *)ipaddr,&server.sin6_addr);
				rc = sendto(s, repl,22, 0,(struct sockaddr*)&server, sizeof(server));
  	  			if(rc<0){
   					perror("sendto");
          	 		}else{
				   printf("network hash bien ete envoyez");	
				}
				taille_accumele=taille_accumele+20;
				point=point+20;
			}


		      if(req[point]==4){
				printf("tlv Network Hash recue\n");
                                unsigned char nh[16];
				memset(nh,0,16);
				networkhash(nh,ld,nbr_donnee);
                                unsigned char nhrecue[16];
				memset(nhrecue,0,16);
                                memmove(nhrecue,&req[point+2],16);
                                if(memcmp(nh,nhrecue,16)!=0){
				   	unsigned char repl[6];
					entet(repl,2);	
					network_state_request(&repl[4]);
					//envoi tlv networkstate request
					inet_ntop(client.sin6_family, &client.sin6_addr, ipstr, sizeof ipstr);

					l = inet_pton(AF_INET6,ipstr,&server.sin6_addr);
					
                                   
          				rc = sendto(s, repl,6, 0,(struct sockaddr*)&server, sizeof(server));
  	  				if(rc<0){
   						perror("sendto");
          	 			}else{
				   		printf("tlv networkstate envoye bien ete envoyez\n");	
					}	
				}
				taille_accumele=taille_accumele+18;
				point=point+18;
				
			}


		if(req[point]==5){
				printf("tlv Network State Request recue\n");
				unsigned char repl[1024];
				memset(repl,0,1024);
                                listeDonnees *q=ld;
				int k;
				int had;
				int had2=nbr_donnee;
				

				while(q!=NULL){
				    if(had2<=36){
					entet(repl,had2*28);
						
					
				    }else{
					entet(repl,36*28);
						
				     }
				    k=4;
				    had=0;
                                while(q!=NULL && had<36){
					send_node_hash(&repl[k],&q->data);
					k=k+28;		   
					q=q->suivant;
					had++;;
				}  
				had2=had2-36;

 				//envoi d'un tlv node hash pour chaque donnée
                                inet_ntop(client.sin6_family, &client.sin6_addr, ipstr, sizeof ipstr);

				l = inet_pton(AF_INET6,ipstr,&server.sin6_addr);
				
                                   
          			rc = sendto(s, repl,(nbr_donnee*28)+4, 0,(struct sockaddr*)&server, sizeof(server));
  	  			if(rc<0){
   					perror("sendto");
          	 		}else{
				   printf("tlv node hash a bien ete envoyez\n");	
				}

				}
				taille_accumele=taille_accumele+2;
				point=point+2;			
		  }


			if(req[point]==6){
				printf("une tlv Node hash recue\n");
				unsigned char id_rec[8];
                                memcpy(id_rec,&req[point+2],8);
				unsigned char hash_recue[16];
				unsigned char seqno_recue[2];
				memcpy(seqno_recue,&req[point+10],2);
				memcpy(hash_recue,&req[point+12],16);	
				listeDonnees *dr;
				dr=trouve(ld,id_rec);
				unsigned char has[16];
	                        if(dr!=NULL){
				nodehash(has,&dr->data);
				if(memcmp(seqno_recue,dr->data.s,2)==0){
					printf("le seqno est identique \n");
					goto ignore;			
				}
				}
				if(dr==NULL || memcmp(hash_recue,has,16)!=0){
					unsigned char repl[14];
					entet(repl,10);
					node_state_request(&repl[4],id_rec);	
					//envoi d'un tlv node state request
                                	inet_ntop(client.sin6_family, &client.sin6_addr, ipstr, sizeof ipstr);

					l = inet_pton(AF_INET6,ipstr,&server.sin6_addr);
						
                                   
          				rc = sendto(s, repl,14, 0,(struct sockaddr*)&server, sizeof(server));
  	  				if(rc<0){
   						perror("sendto");
          	 			}else{
				   		printf("tlv node state request a bien ete envoyez\n");	
					}	
			       }

			      ignore: taille_accumele=taille_accumele+28;
			      	      point=point+28;	
                                 

			}


		     	if(req[point]==7){
				printf("tlv Node State Request recue\n");
				unsigned char id_recue[8];
				memcpy(id_recue,&req[point+2],8);
				listeDonnees *lq;
				lq=trouve(ld,id_recue);
				if(lq!=NULL){
		
				unsigned char repl[strlen((const char *)d.d)+32];
                                NodeState(repl,&lq->data);
                                //envoi d'un tlv node state
                                inet_ntop(client.sin6_family, &client.sin6_addr, ipstr, sizeof ipstr);
			
				l = inet_pton(AF_INET6,ipstr,&server.sin6_addr);
                                  
          			rc = sendto(s, repl,strlen((const char *)d.d)+32, 0,(struct sockaddr*)&server, sizeof(server));
  	  			if(rc<0){
   					perror("sendto");
          	 		}else{
				   printf("tlv node state a bien ete envoyez\n");	
				} 	
				taille_accumele=taille_accumele+10;
				point=point+10;

				}else{
					printf("id non trouvé\n");				
				}
		        }

			if(req[point]==8){
				printf("tlv Node state recue\n");
				uint16_t x=req[point+1];
				unsigned char id_recue[8];
                                memmove(id_recue,&req[point+2],8);
				donnees dc;
				memcpy(dc.i,&req[point+2],8);
                                uint16_t seqno_recue;
				memcpy(&seqno_recue,&req[point+10],2);
				unsigned char seqno_rec[2];
				memcpy(&seqno_rec,&req[point+10],2);					
				unsigned char hash_recue[16];				
				memcpy(hash_recue,&req[point+12],16);			
                                memcpy(&dc.s,&req[point+10],2);
                                unsigned char data_recue[192]; 
                                memcpy(&dc.d,&req[point+26],x-26);	
				unsigned char hash_test[16];
				nodehash(hash_test,&dc);

				if(memcmp(hash_test,hash_recue,16)!=0){
					
			
					printf("sont different\n");
				        char *message="le hash recue n'est pas coherent";
					unsigned char repl[strlen(message)+6];
					warning(repl,message);
					l = inet_pton(AF_INET6,ipstr,&server.sin6_addr);
          				rc = sendto(s, repl,strlen(message)+6, 0,(struct sockaddr*)&server, sizeof(server));
  	  				if(rc<0){
   						perror("sendto");
          	 			}else{
				   		printf("tlv warning a bien ete envoyez\n");	
					}	
				}
			
				memcpy(&data_recue,&req[point+26],x-26);
				
                                listeDonnees *lq;
				lq=trouve(ld,id_recue);
				if(lq!=NULL){
				    if(memcmp(seqno_rec,lq->data.s,2)==0){
					printf("seqno identique dans 8 \n");
					goto ignore2;
                                    }
				    unsigned char ha[16];
				    nodehash(ha,&lq->data);
				    if(memcmp(ha,hash_recue,16)!= 0){
					uint16_t localseqno;
					memcpy(&localseqno,lq->data.s,2);
					if(compare(&seqno_recue,&localseqno)){
					   if(memcmp(ld->data.i,id_recue,8)==0){
						printf("j'ai recue mon id\n");
						modifier_monseqno(ld);
					   }else{
					        memcpy(lq->data.s,&seqno_recue,2);
						memcpy(lq->data.d,data_recue,x-26);	
					   }
					}
			             }	
					
                                }else{
				   ajout_donnees(ld,id_recue,&seqno_recue,data_recue,&nbr_donnee);
				}
	
				ignore2:taille_accumele=taille_accumele+x+2;
					point=point+x+2;		


			}      
		
			}

		
                                 
	        }

		}

		}else{
	        	
                      printf("pas de reponse dans 20 seconds.\n");
		      //parcoure la table de voisins et verifier la date de reception du dernier paquet d'un voisin si >70s on supprime le vosisin 	
		      miseajour_vois(lv, &nbr_v);
		      
		      //si nobre de voisins infirieur a 5 on envoi un nighbourrequest au hasrd 
		      if(nbr_v<5){
				int nbgen=rand()%(nbr_v-1);
				unsigned char repl[6];
		                entet(repl,2);
				listevois *vh=lv;
				
				for(i=0;i<nbgen;i++){
				   vh=vh->suivant;			
				}
				printf("et l'dresse choisi au hasard egale a %s\n",vh->data.hostadresse);
				neighbouRequest(&repl[4]);
				l = inet_pton(AF_INET6,vh->data.hostadresse,&server.sin6_addr);
				if(l<0){
					perror("inet_pton");
				}
				rc = sendto(s, repl,6, 0,(struct sockaddr*)&server, sizeof(server));
		  	  	if(rc<0){
			   	    perror("sendto");
			  	}
				
		       }      
		      //envoyer un network hash a tous mes voisins
		       unsigned char reply[22];
		       memset(reply,0,22);
		       entet(reply,18);
		       netHash(&reply[4],ld,nbr_donnee);
		       listevois *q=lv;
		       for(i=0;i<nbr_v;i++){
			l = inet_pton(AF_INET6,q->data.hostadresse,&server.sin6_addr);
		  	rc = sendto(s,reply,22, 0,(struct sockaddr*)&server, sizeof(server));
	  	  	if(rc<0){
	   		     perror("sendto");
		  	 }else{
				printf("jai envoyer un network hash a l'adrese %s\n",q->data.hostadresse);	
                         }
			q=q->suivant;

		   	}		
			
		}

		}

          
            			

 }

	return 0;
}
