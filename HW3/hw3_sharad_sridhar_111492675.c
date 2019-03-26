#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <getopt.h>

#define DEFAULT_PORT 7777

struct params{
	int sock;
	struct sockaddr_in service_addr;
	unsigned char *key_file;
};

struct ctr_state {
	unsigned char ivec[16];
    unsigned int num;
    unsigned char ecount[16];
};

void init_ctr(struct ctr_state *state, const unsigned char iv[16])
{
	state->num = 0;
	memset(state->ecount, 0, 16);
	memset(state->ivec + 8, 0, 8);
	memcpy(state->ivec, iv, 8);
}

//read the contents of the keyfile
unsigned char* read_file(char* file_name)
{
	char *buffer = NULL;
	long length;
	FILE *f = fopen (file_name, "rb");

	if (f) {
		fseek (f, 0, SEEK_END);
		length = ftell (f);
		fseek (f, 0, SEEK_SET);
		buffer = malloc (length);
		if (buffer)
		{
			fread (buffer, 1, length, f);
		}
		fclose (f);
	}
	return buffer;
}

//create a socket
int create_socket()
{
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(sock_fd < 0)
	{
		fprintf(stderr,"Unable to create socket\n");
		exit(EXIT_FAILURE);
	}
	printf("Socket Created\n");
	return sock_fd;
}

//bind a created socket on the server
void bind_socket(int sock_fd, int port_no)
{
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	address.sin_port = htons(port_no);
	int bind_result = bind(sock_fd, (struct sockaddr*)&address, sizeof(address));
	if(bind_result < 0)
	{
		fprintf(stderr, "Unable to bind socket\n");
		exit(EXIT_FAILURE);
	}
	printf("Socket Bound\n");
	return bind_result;
}

//connect to the server from the client side
void connect_socket(int sock_fd, int port_no, struct hostent* ipaddr)
{
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = ((struct in_addr*)(ipaddr->h_addr))->s_addr;
	address.sin_port = htons(port_no);
	
	int connect_result = connect(sock_fd, (struct sockaddr*)&address, sizeof(address));
	if(connect_result < 0)
	{
		printf("Unable to connect socket\n");
		exit(EXIT_FAILURE);
	}
	printf("Socket connected\n");
	
}

void handleErrors()
{
	unsigned long errCode;

    printf("An error occurred\n");
    while(errCode == ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    abort();
}

void* server_process(void *void_ptr)
{
	unsigned char msg[4096];
	
	struct ctr_state state;
	AES_KEY aes_key;
	unsigned char iv[8];

	if (!void_ptr) 
	{
		pthread_exit(0); 
	}
	struct params *par = (struct params *)void_ptr;
	int sock = par->sock;
	struct sockaddr_in service_address = par->service_addr;
	unsigned char *key = par->key_file;
	
	int service_fd;	
	//creating a socket file descriptor for the communication between server and service
	service_fd = create_socket();
	
	//conect to the service
	int connect_result = connect(service_fd, (struct sockaddr*)&service_address, sizeof(service_address));
	if(connect_result < 0)
	{
		printf("Unable to connect socket to service\n");
		pthread_exit(0);
	}
	printf("Socket connected to service\n");
	
	//set non blocking flags
	int flags = fcntl(sock, F_GETFL);
	if (flags == -1) {
		printf("Sock flag error!...exiting thread...\n");
		close(sock);
		close(service_fd);
		free(par);
		pthread_exit(0);
	}
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	
	flags = fcntl(service_fd, F_GETFL);
	if (flags == -1) {
		printf("read ssh_fd flag error!\n");
		close(sock);
		close(service_fd);
		free(par);
		pthread_exit(0);
	}
	fcntl(service_fd, F_SETFL, flags | O_NONBLOCK);
	
	//set the symmetric key for enceyption and decryption
	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		printf("Set encryption key error!\n");
		exit(1);
	}

	int n;
	int check = 0;
	//start communications
	while (1) {
		//read messages from client
		while ((n = read(sock, msg, 4096)) > 0) {
			if (n < 8) {
				printf("Corrupted packet received\n");
				close(sock);
				close(service_fd);
				free(par);
				pthread_exit(0);
			}
			
			memcpy(iv, msg, 8);			
			init_ctr(&state, iv);
			
			//decrypt message sent by client
			unsigned char client_msg[n-8];
			AES_ctr128_encrypt(msg+8, client_msg, n-8, &aes_key, state.ivec, state.ecount, &state.num);

			//send message to service
			write(service_fd, client_msg, n-8);

			if (n < 4096)
			{
				break;
			}
		};
		
		//read messages from service
		while ((n = read(service_fd, msg, 4096)) >= 0) {
			if (n > 0) {
				int i;
				for(i=0;i<8;i++)
				{
					iv[i] = rand();
				}
				
				//attach iv to the payload
				char *final_msg = (char*)malloc(n + 8);
				memcpy(final_msg, iv, 8);
				
				unsigned char enc_client[n];
				init_ctr(&state, iv);
				
				AES_ctr128_encrypt(msg, enc_client, n, &aes_key, state.ivec, state.ecount, &state.num);
				memcpy(final_msg + 8, enc_client, n);

usleep(1000);
				
				//send the encrypted message and iv to the server
				write(sock, final_msg, n + 8);

				free(final_msg);

			}
			
			if (check == 0 && n == 0)
				check = 1;
			
			if (n < 4096)
				break;
		}

		if (check == 1)
			break;
	}
	
	close(sock);
	close(service_fd);
	free(par);
	pthread_exit(0);
}

void server_side(struct hostent* ipaddr, char* dest_port, char* service_port, unsigned char* key_ptr)
{
	//convert the correspondig ports to their int forms
	int dest_port_no = atoi(dest_port);
	int service_port_no = atoi(service_port);
    
	int server_fd;
	int client_fd;
	struct sockaddr_in address;	
	struct sockaddr_in client;
	unsigned char client_msg[4096] = {0};
	unsigned char server_msg[4096] = {0};
	unsigned char enc_client_msg[4096] = {0};
	unsigned char enc_server_msg[4096] = {0};
	unsigned char service_msg[4096] = {0};
	
	struct sockaddr_in service_address;
	service_address.sin_family = AF_INET;
	service_address.sin_addr.s_addr = ((struct in_addr*)(ipaddr->h_addr))->s_addr;
	service_address.sin_port = htons(service_port_no);
	
	//creating a socket file descriptor for the communication between server and client
	server_fd = create_socket();	
	//binding the socket
	bind_socket(server_fd, dest_port_no);
	
	//start listening
	//only one connection allowed at a time
	int listen_result = listen(server_fd, 1);
	if(listen_result < 0)
	{
		printf("Unable to listen\n");
		exit(EXIT_FAILURE);
	}
	printf("Listening\n");
	
	int client_len = 0;	
	client_len = sizeof(struct sockaddr_in);
	
	struct params* par;
	pthread_t thread;
	while (1) {
		//start accepting connections from the client
		par = (struct params *)malloc(sizeof(struct params));
		client_fd = accept(server_fd, (struct sockaddr*)& client, (socklen_t*)&client_len);
		par->sock = client_fd;
		par->service_addr = service_address;
		par->key_file = key_ptr;
		
		if(client_fd < 0)
		{
			fprintf(stderr, "Unable to accept connection\n");
			free(par);
		}
		else 
		{
			pthread_create(&thread, 0, server_process, (void *)par);
			pthread_detach(thread);
		}
	}
	
	close(server_fd);
	return;
}

void client_side(struct hostent* ipaddr, char* dest_port, unsigned char* key_ptr)
{
	//convert string port number to int
	int dest_port_no = atoi(dest_port);

	int client_fd;
	
	char client_msg[4096] = {0};
	char server_msg[4096] = {0};
	
	//creating a socket file descriptor
	client_fd = create_socket();
	
	//connect the socket
	connect_socket(client_fd, dest_port_no, ipaddr);
	
	//Non blocking calls
	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	int flags = fcntl(client_fd, F_GETFL);
if(flags == -1)
close(client_fd);
fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
	
	//initialize iv
	struct ctr_state state;
	unsigned char iv[8];
	AES_KEY aes_key;

	//set AES key
	if (AES_set_encrypt_key(key_ptr, 128, &aes_key) < 0) {
		fprintf(stderr,"Set encryption key error!\n");
		exit(1);
	}
	
	int n=0;
	//Start communication
	while(1) 
	{
		//read from console and send it to the server after encryption
		while ((n = read(STDIN_FILENO, server_msg, 4096)) > 0) {
						
			int i;
			for(i=0;i<8;i++)
			{
				iv[i] = rand();
			}

			//attach iv to the payload
			char *final_msg = (char*)malloc(n + 8);
			memcpy(final_msg, iv, 8);
			
			unsigned char enc_client[n];
			init_ctr(&state, iv);
			
			AES_ctr128_encrypt(server_msg, enc_client, n, &aes_key, state.ivec, state.ecount, &state.num);
			memcpy(final_msg + 8, enc_client, n);
			
			//send the encrypted message and iv to the server
			write(client_fd, final_msg, n + 8);

			free(final_msg);

			//check if more bytes are to be read
			if (n < 4096)
			{
				//no need to wait for any read
				break;
			}
		}

		//read replies from the server
		while ((n = read(client_fd, server_msg, 4096)) > 0) {
			if (n < 8) {
				//the iv itself is of length 8, so the packet size cannot be <8
				fprintf(stderr, "Corrupted packet received\n");
				close(client_fd);
				return;
			}

			//initialize iv from the first part of the payload
			memcpy(iv, server_msg, 8);
			unsigned char dec_serv[n - 8];
			
			//decrypt the incoming payload
			init_ctr(&state, iv);
			AES_ctr128_encrypt(server_msg + 8, dec_serv, n - 8, &aes_key, state.ivec, state.ecount, &state.num);

			write(STDOUT_FILENO, dec_serv, n - 8);

			if (n < 4096)
			{
				break;
			}
		}
	}
	close(client_fd);
	return;		
	
}


int main(int argc, char **argv)
{
	
	OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();    
    
    //port for the client_server connection
    char* cur_port = NULL;
    //symmetric keyfile name
    char* key_file = NULL;
    
    int mode = 1; //0 for server and 1 for client, client by default
    
    int option = 0;
	while((option = getopt(argc, argv, "k:l:"))!= -1)
	{
		switch(option)
		{
			case 'k':
				//Use the symmetric key contained in keyfile (as a hexadecimal string)
				key_file = optarg;
				break;
			case 'l':
				//Reverse proxy mode: Listen for inbound connections on port and relay them to the service
				cur_port = optarg;
				mode = 0;
				break;
			case '?':
				if(optopt == 'l')
				{
					fprintf(stderr, "No port number was specified for the reverse proxy mode");
					return(-2);
				}
				else if(optopt == 'k')
				{
					fprintf(stderr, "No keyfile was specified");
					return(-2);
				}
				else
				{
					fprintf(stderr, "Invalid argument");
					return(-2);
				}
			default:
				fprintf(stderr, "Unknown Error");
				return(-2);
		}
	}
	
	//For obtaining the rest of the arguments, I assumed that the first non-option argument is the ip and the second is the port
	//Any extra arguments are ignored
	//ipaddress of the system
	char* ipaddr = NULL;
	char* dest_port = NULL;
	ipaddr = argv[optind];
	dest_port = argv[optind+1];
	puts(ipaddr);
	if(ipaddr == NULL)
	{
		fprintf(stderr, "No machine specified\n");
		return (-2);
	}
	if(dest_port == NULL)
	{
		fprintf(stderr, "No destination port specified\n");
		return (-2);
	}
	
	//read the key from the file specified
	unsigned char *key_file_ptr = read_file(key_file);
	if(key_file_ptr == NULL)
	{
		fprintf(stderr,"Unable to read Key_File, Exiting...\n");
		return(-2);
	}
	
	struct hostent *host = gethostbyname(ipaddr);
	if (host == 0) {
		fprintf(stderr, "Unable to resolve host name\n");
		return(-2);
	}
	
	
	if(mode ==0)
	{
		//Initialize operations for Server mode
		server_side(host,cur_port, dest_port,key_file_ptr);
	}
	else
	{
		//Initialize operations for Client mode
		client_side(host, dest_port, key_file_ptr);
	}
	
	free(key_file_ptr);	
	
	return 0;
}
