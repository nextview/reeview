#include <net/if.h>
#include <sys/ioctl.h>
#include <string.h>
#include <dlfcn.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <wchar.h>

#include <windows.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <pthread.h>

#include "osdep.h"
#include "tap-win32/common.h"

#define BUFSIZE 0x3E8000 
/*!
	\def BUFSIZE
 
	\brief Tamaño estandar para la inicializacion de una libreria 
	desconocida

	Se supone que es el tamaño de un buffer, pero se desconoce su 
procedencia y su importancia. En algún momento descubriremos para qué sirve

*/

/*! 
	\struct CV_Header

	Esta estructura parece que es necesaria usarla, pero al
	parecer, no se sabe muy bien lo que es. 

*/
struct CV_Header {
        unsigned int TickCount; // GetTickCount() / 1000 at time of packet
        unsigned int Micros;    // Microsecond counter at time of packet
        /* The following might be backwards, unsure */
        int PacketSize;         // Full packet size?
        int SliceSize;          // Truncated packet size?
        int Unknown;            // Not sure what this is.
};

/*!
	\struct CV_Header2

	Esta estructura, parece que es una cabecera sobre los datos que da el
	sistema para saber si se ha recibido bien el paquete.

*/
struct CV_Header2 {
        char ErrorFlag;   // ErrorFlag & 1 = CRC error
        char Unknown2[6]; // Unknown
        char Power;       // Power
        char Unknown3[6]; // Unknown
};


/*!

	\struct cstate

	Declara una variable llamada _cs, que parece ser una especie de super estructura
	que utiliza para almacenar todo tipo de información sobre el estado de la conexión 

*/

struct cstate {
	char		cs_param[256];
	int		cs_ioctls;
	struct ifreq	cs_ifreq;
	char		cs_guid[256];
	HKEY		cs_key;
	int		cs_chan;
	volatile int	cs_restarting;
	void		*cs_lib; // Puntero a libreria dinamica para las funciones de abajo
	pthread_mutex_t	cs_mtx; // un mecanismo de control de sincronizacion mutex
	int		cs_debug;
	
/*
 * Aqui se guardaran los punteros a funciones que estan dentro de una dll
 */
	char		(__cdecl *cs_F1)(int Code);
	char		(__cdecl *cs_F2)(void);
	char		(__cdecl *cs_T1)(int Size, unsigned char *Buffer);
	char		(__cdecl *cs_CC)(int Channel);
	char		(__cdecl *cs_S1)(int Channel);
	int		(__cdecl *cs_S5)(unsigned char *Buffer, int Length);
	int		(__cdecl *cs_GN)(wchar_t *);
	int		(*cs_SC)(int band);
} _cs;

/*!

	\fn static struct cstate *get_cs(void) 
	
	\brief Devuelve la estructura global _cs
	

*/
 
static struct cstate *get_cs(void) 
{
	return &_cs; 
}

static int print_error(char *fmt, ...) // ... -> es una manera de decir que recibe un numero indeterminado de argumentos
{
	va_list ap;

	va_start(ap, fmt);// Inicializa la variable ap para que lo pueda usar 
	vprintf(fmt, ap);// Segun lo que he visto, esta función imprime todo lo que le llega.
	va_end(ap);// Libera la variable ap
	printf("\n"); // Y pone un salto de linea en el la pantalla (seguramente log)

	return -1; // Devuelve error
}

static void print_debug(char *fmt, ...)
{
	struct cstate *cs = get_cs(); //inicializa la direccion de la variable cs a la de _cs
	va_list ap; // Crea una variable de control de argumentos variables

	if (!cs->cs_debug) // Comprueba que esté configurado en modo debug
		return; // Sale si no lo esta

	va_start(ap, fmt); //Inicializa la variable de lista
	vprintf(fmt, ap); // Saca un solo argumento de tipo desconocido
	va_end(ap); // Libera la variable ap
	printf("\n"); // Pone un salto de linea
}

static int do_init_lib(struct cstate *cs)
{
/*
 * Esta función inicializa las librerias a traves de los punteros a funciones de la estructura
 */
	/* init */
        if (!cs->cs_F1(BUFSIZE))
		return print_error("F1");
       
       	/* start monitor */
        if (!cs->cs_S1(cs->cs_chan))
		return print_error("S1");

	/* change chan */
	if (!cs->cs_CC(cs->cs_chan))
		return print_error("CC");

	return 0;
}

static int init_lib(struct cstate *cs)
{
	char *lib = "ca2k.dll";// Se guarda en un array el nombre de una libreria dinamica
	void *ca2k_dll; // puntero de una dll

	ca2k_dll = dlopen(lib, RTLD_LAZY); // Se abre la libreria dinamica
	if (!ca2k_dll) 
		return print_error("dlopen(%s)", lib);
	cs->cs_lib = ca2k_dll; // Se guarda el puntero a la libreria en cs_lib

        // Initialise
        cs->cs_F1 = dlsym(ca2k_dll, "F1");
        // Transmit
        cs->cs_T1 = dlsym(ca2k_dll, "T1");
        // Change monitoring channel
        cs->cs_CC = dlsym(ca2k_dll, "CC");
        // Start monitoring
        cs->cs_S1 = dlsym(ca2k_dll, "S1");
        // Read packets
        cs->cs_S5 = dlsym(ca2k_dll, "S5");
	// Finalize
	cs->cs_F2 = dlsym(ca2k_dll, "F2");
	// Get Adapter Name 
	cs->cs_GN = dlsym(ca2k_dll, "GN");

// los nombres "F1","T1" deben estar definidos en algun sitio.. habra que buscar

/*
 * Si no se han inicializado todas la funciones, salta error, y acaba inicializando
 * las librerias
 */
	
        if (!(cs->cs_F1 && cs->cs_T1 && cs->cs_CC && cs->cs_S1 && cs->cs_S5
	      && cs->cs_F2 && cs->cs_GN))
		return print_error("Can't find syms");

	return do_init_lib(cs);
}

static int get_name(struct cstate *cs, char *name)
{
	wchar_t wname[1024]; // tipo de dato valido para utilizar caracteres no ASCII
	unsigned int i;

	if (!(cs->cs_GN(wname) & 1) ) // En teoria, con esto esta consiguiendo el nombre del ap
		return print_error("GN()"); // Si no devuelve nada, aqui se devuelve -1

	/* XXX */
	for (i = 0; i < (sizeof(wname)/sizeof(wchar_t)); i++) { // localizamos cuantos caracteres tiene el nombre
		if (wname[i] == 0)
			break;

		*name++ = (char) ((unsigned char) wname[i]); // No estoy seguro de que es esto
/*
 * Parece que es una especie de contador, pero no entiendo el sentido de poner ese igual
 * ya lo repasare mas tarde.
 * Acabo de darme cuenta de que es posible que lo que este haciendo, sea que ya que no va a volver a pasar por ese
 * puntero, puede estar modificando directamente el puntero del nombre, en cuyo caso, estaria convirtiendo el nombre a 
 * un char (¿¿??), con su consiguiente perdida de informacion, y finalizando el array para darle el tratamiento de un
 * string
 */
	}
	*name = 0;

	return 0;
}

static int get_guid(struct cstate *cs, char *param)
{
	IP_ADAPTER_INFO ai[16]; /* 
				 * No entiendo el sentido de tener espacio para 16 adaptadores de red de todos modos
				 * esta estructura es de Windows: http://msdn.microsoft.com/en-us/library/aa366062(v=vs.85).aspx
				 */	
	DWORD len = sizeof(ai); // Esta parece estar destinada a tener el tamaño que ocupa un puntero a estructura 
				// http://msdn.microsoft.com/en-us/library/cc230318
	PIP_ADAPTER_INFO p; // Este parece ser un puntero a una estructura de adaptador
	char name[1024]; // Sitio para el nombre
	int found; // Esto tiene toda la pinta de ser un flag

	if (get_name(cs, name) == -1)
		return print_error("get_name()");

	print_debug("Name: %s", name);

	if (GetAdaptersInfo(ai, &len) != ERROR_SUCCESS) 
		return print_error("GetAdaptersInfo()"); // Esto debe de ser para conseguir informacion del adaptador 

	p = ai;// Se copia lo conseguido a p
	while (p) {
		print_debug("get_guid: name: %s desc: %s",
			    p->AdapterName, p->Description);

		found = (param && strcmp(p->AdapterName, param) == 0)
			|| strstr(p->Description, name); // Aqui comprobamos si hemos encontrado lo que queriamos que sera?

		/* XXX */
		if (cs->cs_debug) { // Parece de por si queremos debuguear...
			char yea[512]; // Esto esta para dar falsos positivos si se queria

			printf("Does this look like your card? [y/n]\n");
			yea[0] = 0;
			fgets(yea, sizeof(yea), stdin);
			if (yea[0] == 'y')
				found = 1; 
			else
				found = 0;
		}
		
		if (found) {
			snprintf(cs->cs_guid, sizeof(cs->cs_guid)-1, "%s",
				 p->AdapterName); // Aqui escribe p-> AdapterName a cs->cs_guid
			return 0;
		}

		p = p->Next;
	}

	return print_error("Adapter not found");
}

static int open_key(struct cstate *cs, char *name)
{
	char key[256];
	DWORD dt, len = sizeof(key);

	/* open key */
	snprintf(key, sizeof(key)-1, "%s\\%s", ADAPTER_KEY, name);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_ALL_ACCESS, &cs->cs_key) != ERROR_SUCCESS)
		return print_error("RegOpenKeyEx()");
/*
 * Aqui parece que acaba de abrir un registro, y en el siguiente, compara el valor del registro con ¿¿REG_SZ??
 */

	/* check if its our guid */
	if ((RegQueryValueEx(cs->cs_key, "NetCfgInstanceId", NULL, &dt, (unsigned char*)key, &len) == ERROR_SUCCESS) && (dt == REG_SZ) && (strcmp(key, cs->cs_guid) == 0))
		return 1; /* closekey done by cleanup */

	/* nope */

	RegCloseKey(cs->cs_key);
	cs->cs_key = NULL;

	return 0;
}

static int open_conf(struct cstate *cs)
{
        HKEY ak47; // variable de llave de registro
	int rc = -1;
	int i;
	char name[256];
	DWORD len;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &ak47)
	    != ERROR_SUCCESS) // ERROR_SUCCESS parece ser lo que se devuelve cuando sale BIEN
		return print_error("RegOpenKeyEx()");

	for (i = 0;; i++) 
	{
		len = sizeof(name);
		if (RegEnumKeyEx(ak47, i, name, &len, NULL, NULL, NULL, NULL)!= ERROR_SUCCESS)
			break;

		rc = open_key(cs, name);
		if (rc)
			break;
		else
			rc = -1;
	}


		RegCloseKey(ak47);
	return rc;
}

static int check_param(struct cstate *cs, char **p)
{
	char *param = *p;

	/* assume it's ifname */
	if (strncmp(param, "eth", 3) == 0) 
	{
		snprintf(cs->cs_param, sizeof(cs->cs_param), "%s", param);//Parece que tiene la mania de meter los strings en la estructura con esta funcion
		snprintf(cs->cs_ifreq.ifr_name, sizeof(cs->cs_ifreq.ifr_name), "%s", cs->cs_param);
		
		cs->cs_ioctls = socket(PF_INET, SOCK_DGRAM, 0);
		if (cs->cs_ioctls == -1) 
		{
			cs->cs_ioctls = 0;
			return print_error("socket()");
		}
	}
	else if(strcmp(param, "debug") == 0) 
	{
		cs->cs_debug = 1;
		*p = NULL;
	}

	return 0;
}

int cygwin_init(char *param)
{
	struct cstate *cs = get_cs();

	memset(cs, 0, sizeof(*cs));
	cs->cs_chan = 1;

	if (pthread_mutex_init(&cs->cs_mtx, NULL))
		return print_error("pthread_mutex_init()");

	if (param) 
	{
		if (check_param(cs, &param))
			return -1;
	}

	if (init_lib(cs) == -1)
		return print_error("init_lib()");

	if (get_guid(cs, param) == -1)
		return print_error("get_guid()");

	if (open_conf(cs) == -1)
		return print_error("open_conf()");

	return 0;
}

int cygwin_set_chan(int chan)
{
	struct cstate *cs = get_cs();

	if (!cs->cs_CC(chan))
		return -1;

	cs->cs_chan = chan;

	return 0;
}

int cygwin_inject(void *buf, int len, struct tx_info *ti)
{
	struct cstate *cs = get_cs();

	if (ti) {} /* XXX unused */

	if (!cs->cs_T1(len, buf))
		return -1;

	return len;
}

static int read_single_packet(struct cstate *cs, unsigned char *buf, int len,
			      struct rx_info *ri)
{          
        static unsigned char data[BUFSIZE];
        static int totlen = 0;
        static unsigned char *next;
        struct CV_Header *cvh;
        struct CV_Header2 *cvh2;
        unsigned char *hdr;
        int align, plen;
        
        /* read data if necessary */
        if (totlen == 0) 
	{
		/* XXX can't kill iface if we're reading */
		if (pthread_mutex_lock(&cs->cs_mtx))
			return -1;
                totlen = cs->cs_S5(data, sizeof(data));
		if (pthread_mutex_unlock(&cs->cs_mtx))
			return -1;

                if (totlen < 1)
			return -1;

                next = data;
        }

        /* copy packet */
        cvh = (struct CV_Header*) next;
        cvh2 = (struct CV_Header2*) (cvh+1);
        hdr = (unsigned char*) (cvh2+1);
        plen = cvh->SliceSize - sizeof(*cvh2);
        assert(plen > 0);
        if (plen < len)
                len = plen;
        memcpy(buf, hdr, len);

	if (ri)
		ri->ri_power = cvh2->Power;

        /* go to next packet */
        next = hdr + plen;
        align = ((unsigned long)next - (unsigned long)cvh ) % 4;
        if (align)
                align = 4 - align;
        next += align;
        totlen -= sizeof(*cvh) + cvh->SliceSize;
        assert(totlen >= 0);
        if (totlen > 0)
                totlen -= align;
        assert(totlen >= 0);

        return (cvh2->ErrorFlag & 1) ? 0 : len;
}

int cygwin_sniff(void *buf, int len, struct rx_info *ri)
{
	struct cstate *cs = get_cs();
        int rc;
	int tries = 60;

        while ((rc = read_single_packet(cs, buf, len, ri)) == 0);

	if (rc != -1)
		return rc;

	/* check if we're restarting */
	while (cs->cs_restarting && tries--) 
	{
		/* try again */
		if (cs->cs_restarting == 2) 
		{
			cs->cs_restarting = 0;
			return cygwin_sniff(buf, len, ri);
		}

		sleep(1);
	}

        return rc;
}

static int do_get_mac_win(struct cstate *cs, unsigned char *mac)
{
	IP_ADAPTER_INFO ai[16];
	DWORD len = sizeof(ai);
	PIP_ADAPTER_INFO p;

	if (GetAdaptersInfo(ai, &len) != ERROR_SUCCESS)
		return -1;

	p = ai;
	while (p) 
	{
		if (strcmp(cs->cs_guid, p->AdapterName) == 0) 
		{
			memcpy(mac, p->Address, 6);
			return 0;
		}

		p = p->Next;
	}

	return -1;
}

static int do_get_mac_cygwin(struct cstate *cs, unsigned char *mac)
{
	if (ioctl(cs->cs_ioctls, SIOCGIFHWADDR, &cs->cs_ifreq) == -1)
		return -1;

	memcpy(mac, cs->cs_ifreq.ifr_addr.sa_data, 6);

	return 0;
}

int cygwin_get_mac(unsigned char *mac)
{
	struct cstate *cs = get_cs();

	if (cs->cs_ioctls)
		return do_get_mac_cygwin(cs, mac);
	
	return do_get_mac_win(cs, mac);
}

static int is_us2(struct cstate *cs, HDEVINFO *hdi, SP_DEVINFO_DATA *did)
{             
        char buf[256];
        DWORD len = sizeof(buf), dt;
              
        if (cs) {} /* XXX unused */
              
        if (!SetupDiGetDeviceRegistryProperty(*hdi, did, SPDRP_DEVICEDESC, &dt, (unsigned char*)buf, len, &len))
                return 0;
              
        if (dt != REG_SZ)
                return 0;

	return strstr(buf, "CommView") != NULL;
}

static int reset_state(HDEVINFO *hdi, SP_DEVINFO_DATA *did, DWORD state)
{
        SP_PROPCHANGE_PARAMS parm;
        
        parm.ClassInstallHeader.cbSize = sizeof(parm.ClassInstallHeader);
        parm.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        parm.Scope = DICS_FLAG_GLOBAL;
        parm.StateChange = state;

        if (!SetupDiSetClassInstallParams(*hdi, did, (SP_CLASSINSTALL_HEADER*)&parm, sizeof(parm)))
                return -1;

        if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, *hdi, did))
                return -1;

        return 0;
}

static int do_reset(HDEVINFO *hdi, SP_DEVINFO_DATA *did)
{
        int rc;

        rc = reset_state(hdi, did, DICS_DISABLE);
        if (rc)
                return rc;

        return reset_state(hdi, did, DICS_ENABLE);
}

static int restart(struct cstate *cs)
{
	int rc;
	
	rc = do_init_lib(cs);

	return rc;
}

static int reset(struct cstate *cs)
{
        HDEVINFO hdi;
        SP_DEVINFO_DATA did;
        int i;
        int rc = -1;

        hdi = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL,
                          DIGCF_PRESENT);
        if (hdi == INVALID_HANDLE_VALUE)
                return -1;

        /* find device */
        for (i = 0;; i++) {
                did.cbSize = sizeof(did);
                if (!SetupDiEnumDeviceInfo(hdi, i, &did))
                        break;
                
                if (!is_us2(cs, &hdi, &did))
                        continue;

		/* XXX we are blocked on reader.  */
		if (pthread_mutex_lock(&cs->cs_mtx))
			break;
		cs->cs_restarting = 1;

		/* kill lib */
		if (!cs->cs_F2())
			break;

		/* reset NIC */
                rc = do_reset(&hdi, &did);
                if (rc) 
                        break;

		sleep(1); /* XXX seems necessary */

		/* reinit lib */
                rc = restart(cs);
		cs->cs_restarting = 2;
		
		/* done */
		if (pthread_mutex_unlock(&cs->cs_mtx))
			break;

                break;
        }
        
        SetupDiDestroyDeviceInfoList(hdi);

        return rc;
}

int cygwin_set_mac(unsigned char *mac)
{
	struct cstate *cs = get_cs();
        char str[2*6+1];
	char strold[sizeof(str)];
        int i;
	char *key = "NetworkAddress";
	DWORD dt, len = sizeof(strold);
        
	/* convert */
        str[0] = 0;
        for (i = 0; i < 6; i++) 
	{
                char tmp[3];        
                if (sprintf(tmp, "%.2X", *mac++) != 2)
			return -1;
                strcat(str, tmp);
        }

	/* check old */
	if ((RegQueryValueEx(cs->cs_key, key, NULL, &dt, (unsigned char*)strold, &len) == ERROR_SUCCESS) && (dt == REG_SZ)) 
	{
		if (strcmp(str, strold) == 0)
			return 0;
	}
       
	/* set */
	if (RegSetValueEx(cs->cs_key, key, 0, REG_SZ, (unsigned char *)str, strlen(str)+1) != ERROR_SUCCESS)
                return -1;
              
        if (reset(cs) == -1)
                return -1;

        return 0;
}

void cygwin_close(void)
{
	struct cstate *cs = get_cs();

	if (cs->cs_ioctls)
		close(cs->cs_ioctls);

	if (cs->cs_key)
		RegCloseKey(cs->cs_key);

	if (cs->cs_lib) 
	{
		cs->cs_F2();
		dlclose(cs->cs_lib);
	}
}
