#include "openssl/dgtls10gc.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int splitStr(char *str, char *arrStr[], char splitter) 
{
    int arrIndex = 0;
    int splitEn = 1;

    while (*str != '\0') {
        if (*str == splitter) {
            *str = '\0';
            splitEn = 1;
        } else if (splitEn == 1) {
            arrStr[arrIndex++] = str;
            splitEn = 0;
            if (arrIndex >= 16) {
                break;
            }
        }
        ++str;
    }

    return arrIndex;
}

// convert string to a 32-bit array
uint32_t* string_to_uint32_array(const char* str, size_t *out_size) {
    size_t len = strlen(str);
    size_t num_ints = (len + 7) / 8; // Calculate number of 32-bit integers needed
    uint32_t* result = (uint32_t*)malloc(num_ints * sizeof(uint32_t));
    uint8_t temp8b;
    
    if (!result) {
        // Handle memory allocation failure
        *out_size = 0;
        return NULL;
    }
    *out_size = num_ints;

    for (size_t i = 0; i < num_ints; ++i) {
        uint32_t value = 0;
        // Pack up to 8 characters into a uint32_t (mix endian: little-endian in word and big-endian in addr)
        // ex: "123456789ABCDEF0" =>    array[0] = 0x12345678
        //                              array[1] = 0x9ABCDEF0
        for (size_t j = 0; j < 8; ++j) {
            size_t char_index = i * 8 + j;
            if (char_index < len) {
                temp8b = str[char_index];
                if ( ('0' <= temp8b) && (temp8b <= '9') ) {
                    // 0-9
                    temp8b = temp8b - '0';
                } else if ( ('A' <= temp8b) && (temp8b <= 'F') ) {
                    // A-F
                    temp8b = temp8b - 'A' + 10;
                } else if ( ('a' <= temp8b) && (temp8b <= 'f') ) {
                    // a-f
                    temp8b = temp8b - 'a' + 10;
                } else {
                    printf("Invalid key value\r\n");
                    return 0;
                }
                value = (value << 4) | (uint32_t)(temp8b);
            } else {
                // Handle padding with zeroes
                value = (value<<4) | (uint32_t)('\0');
            }
        }

        result[i] = value;
    }
    return result;
}

// MARK: Keylog call back function
void dg_keylog_callback(const SSL *ssl, const char *line) {
    char * arrStr[16];
    splitStr((char*)line, arrStr, ' ');

    size_t output_size;
    uint32_t* array = string_to_uint32_array(arrStr[2], &output_size);

    if (array){
        if (strcmp(arrStr[0], "CLIENT_TRAFFIC_SECRET_0") == 0)
        {
            for (int i=0; i<12; i++)
                regWrite(CTS_IN_REG+i, ((array[i]&0xFF000000)>>24) | ((array[i]&0x00FF0000)>>8) | ((array[i]&0x0000FF00)<<8) | ((array[i]&0x000000FF)<<24) );
            regWrite(CTS_IN_VALID_REG, 1);

        } else if (strcmp(arrStr[0], "SERVER_TRAFFIC_SECRET_0") == 0)
        {
            for (int i=0; i<12; i++)
                regWrite(STS_IN_REG+i, ((array[i]&0xFF000000)>>24) | ((array[i]&0x00FF0000)>>8) | ((array[i]&0x0000FF00)<<8) | ((array[i]&0x000000FF)<<24) );
            regWrite(STS_IN_VALID_REG, 1);

        }
    } else {
        printf("OpenSSL dg_keylog_callback: Something went wrong!!\r\n");
    }
}

// MARK: ssl_info_callback
void dg_ssl_info_callback(const SSL *s, int where, int ret)
{
    // set alert code
    uint32_t alertCode = ( ret & 0x0000FFFF );
    char alertLevel = alertCode>>8;
    if ( alertLevel!=0 ) {
        if ( alertLevel==0x02 ) {
            // Fatal alert code, write to hardware
            regWrite(TLS_ALERT_REG, alertCode);
        } 
    }
}

// MARK: regRead
uint32_t regRead(uint32_t * mem_ptr, uint32_t * value){
    
    const char *econn = getenv("ECONN");
	if ( (econn!=NULL) && strcmp("10",econn)==0 ){
        int mem_fd;
        void *base;
        uint32_t *offset;
        long pagesize;
        
        off_t addr = (off_t)mem_ptr;

        // Get the page size
        pagesize = sysconf(_SC_PAGE_SIZE);
        if (pagesize <= 0) {
            perror("sysconf");
            return -1;
        }
        // Open /dev/mem
        mem_fd = open("/dev/mem", O_RDONLY | O_SYNC);
        if (mem_fd < 0) {
            perror("open /dev/mem failed");
            return -1;
        }
        // Memory map the specified address
        base = mmap(NULL, pagesize, PROT_READ, MAP_SHARED, mem_fd, addr & ~(pagesize - 1));
        if (base == MAP_FAILED) {
            perror("mmap failed");
            close(mem_fd); // Close the file descriptor before returning
            return -1;
        }
        // Calculate the offset within the page
        offset = (uint32_t *)( (uint64_t)base + (addr & (pagesize - 1)));
        // read data
        *value = *(volatile uint32_t *)offset;
        // Unmap the memory
        if (munmap(base, pagesize)) {
            perror("munmap failed");
        }
        // Close the file descriptor
        if (close(mem_fd)) {
            perror("cannot close /dev/mem");
        }
    } else {
        *value = *value;
    }

    return 0;
}

// MARK: regWrite
uint32_t regWrite(uint32_t * mem_ptr, uint32_t value)
{
    const char *econn = getenv("ECONN");
	if ( (econn!=NULL) && strcmp("10",econn)==0 ){
        int mem_fd;
        void *base;
        uint32_t *offset;
        long pagesize;
        
        off_t addr = (off_t)mem_ptr;

        // Get the page size
        pagesize = sysconf(_SC_PAGE_SIZE);
        if (pagesize <= 0) {
            perror("sysconf");
            return -1;
        }
        // Open /dev/mem for writing
        mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
        if (mem_fd < 0) {
            perror("open /dev/mem failed");
            return -1;
        }
        // Memory map the specified address with read and write permissions
        base = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, addr & ~(pagesize - 1));
        if (base == MAP_FAILED) {
            perror("mmap failed");
            close(mem_fd); // Close the file descriptor before returning
            return -1;
        }
        // Calculate the offset within the page
        offset = (uint32_t *)( (uint64_t)base + (addr & (pagesize - 1)));
        *(volatile uint32_t *)offset = (uint32_t)value;
        // Unmap the memory
        if (munmap(base, pagesize)) {
            perror("munmap failed");
        }
        // Close the file descriptor
        if (close(mem_fd)) {
            perror("cannot close /dev/mem");
        }
    }

    return 0;
}

//---------------------------------------------------------------------------
const char* errno_to_name(int errnum) {
    switch (errnum) {
        case E2BIG: return "E2BIG";
        case EACCES: return "EACCES";
        case EADDRINUSE: return "EADDRINUSE";
        case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
        case EAFNOSUPPORT: return "EAFNOSUPPORT";
        case EAGAIN: return "EAGAIN";
        case EALREADY: return "EALREADY";
        case EBADE: return "EBADE";
        case EBADF: return "EBADF";
        case EBADFD: return "EBADFD";
        case EBADMSG: return "EBADMSG";
        case EBADR: return "EBADR";
        case EBADRQC: return "EBADRQC";
        case EBADSLT: return "EBADSLT";
        case EBUSY: return "EBUSY";
        case ECANCELED: return "ECANCELED";
        case ECHILD: return "ECHILD";
        case ECHRNG: return "ECHRNG";
        case ECOMM: return "ECOMM";
        case ECONNABORTED: return "ECONNABORTED";
        case ECONNREFUSED: return "ECONNREFUSED";
        case ECONNRESET: return "ECONNRESET";
        case EDEADLOCK: return "EDEADLOCK";
        case EDESTADDRREQ: return "EDESTADDRREQ";
        case EDOM: return "EDOM";
        case EDQUOT: return "EDQUOT";
        case EEXIST: return "EEXIST";
        case EFAULT: return "EFAULT";
        case EFBIG: return "EFBIG";
        case EHOSTDOWN: return "EHOSTDOWN";
        case EHOSTUNREACH: return "EHOSTUNREACH";
        case EHWPOISON: return "EHWPOISON";
        case EIDRM: return "EIDRM";
        case EILSEQ: return "EILSEQ";
        case EINPROGRESS: return "EINPROGRESS";
        case EINTR: return "EINTR";
        case EINVAL: return "EINVAL";
        case EIO: return "EIO";
        case EISCONN: return "EISCONN";
        case EISDIR: return "EISDIR";
        case EISNAM: return "EISNAM";
        case EKEYEXPIRED: return "EKEYEXPIRED";
        case EKEYREJECTED: return "EKEYREJECTED";
        case EKEYREVOKED: return "EKEYREVOKED";
        case EL2HLT: return "EL2HLT";
        case EL2NSYNC: return "EL2NSYNC";
        case EL3HLT: return "EL3HLT";
        case EL3RST: return "EL3RST";
        case ELIBACC: return "ELIBACC";
        case ELIBBAD: return "ELIBBAD";
        case ELIBMAX: return "ELIBMAX";
        case ELIBSCN: return "ELIBSCN";
        case ELIBEXEC: return "ELIBEXEC";
        case ELNRNG: return "ELNRNG";
        case ELOOP: return "ELOOP";
        case EMEDIUMTYPE: return "EMEDIUMTYPE";
        case EMFILE: return "EMFILE";
        case EMLINK: return "EMLINK";
        case EMSGSIZE: return "EMSGSIZE";
        case EMULTIHOP: return "EMULTIHOP";
        case ENAMETOOLONG: return "ENAMETOOLONG";
        case ENETDOWN: return "ENETDOWN";
        case ENETRESET: return "ENETRESET";
        case ENETUNREACH: return "ENETUNREACH";
        case ENFILE: return "ENFILE";
        case ENOANO: return "ENOANO";
        case ENOBUFS: return "ENOBUFS";
        case ENODATA: return "ENODATA";
        case ENODEV: return "ENODEV";
        case ENOENT: return "ENOENT";
        case ENOEXEC: return "ENOEXEC";
        case ENOKEY: return "ENOKEY";
        case ENOLCK: return "ENOLCK";
        case ENOLINK: return "ENOLINK";
        case ENOMEDIUM: return "ENOMEDIUM";
        case ENOMEM: return "ENOMEM";
        case ENOMSG: return "ENOMSG";
        case ENONET: return "ENONET";
        case ENOPKG: return "ENOPKG";
        case ENOPROTOOPT: return "ENOPROTOOPT";
        case ENOSPC: return "ENOSPC";
        case ENOSR: return "ENOSR";
        case ENOSTR: return "ENOSTR";
        case ENOSYS: return "ENOSYS";
        case ENOTBLK: return "ENOTBLK";
        case ENOTCONN: return "ENOTCONN";
        case ENOTDIR: return "ENOTDIR";
        case ENOTEMPTY: return "ENOTEMPTY";
        case ENOTRECOVERABLE: return "ENOTRECOVERABLE";
        case ENOTSOCK: return "ENOTSOCK";
        case ENOTSUP: return "ENOTSUP";
        case ENOTTY: return "ENOTTY";
        case ENOTUNIQ: return "ENOTUNIQ";
        case ENXIO: return "ENXIO";
        case EOVERFLOW: return "EOVERFLOW";
        case EOWNERDEAD: return "EOWNERDEAD";
        case EPERM: return "EPERM";
        case EPFNOSUPPORT: return "EPFNOSUPPORT";
        case EPIPE: return "EPIPE";
        case EPROTO: return "EPROTO";
        case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
        case EPROTOTYPE: return "EPROTOTYPE";
        case ERANGE: return "ERANGE";
        case EREMCHG: return "EREMCHG";
        case EREMOTE: return "EREMOTE";
        case EREMOTEIO: return "EREMOTEIO";
        case ERESTART: return "ERESTART";
        case ERFKILL: return "ERFKILL";
        case EROFS: return "EROFS";
        case ESHUTDOWN: return "ESHUTDOWN";
        case ESPIPE: return "ESPIPE";
        case ESOCKTNOSUPPORT: return "ESOCKTNOSUPPORT";
        case ESRCH: return "ESRCH";
        case ESTALE: return "ESTALE";
        case ESTRPIPE: return "ESTRPIPE";
        case ETIME: return "ETIME";
        case ETIMEDOUT: return "ETIMEDOUT";
        case ETOOMANYREFS: return "ETOOMANYREFS";
        case ETXTBSY: return "ETXTBSY";
        case EUCLEAN: return "EUCLEAN";
        case EUNATCH: return "EUNATCH";
        case EUSERS: return "EUSERS";
        case EXDEV: return "EXDEV";
        case EXFULL: return "EXFULL";
        default: return "Unknown error";
    }
}

//MARK: Get Phys address
uint64_t get_phys_addr(const char *devicefilename) {
    unsigned char  attr[1024];
    uint64_t  phys_addr;
    int fd  = open(devicefilename, O_RDONLY);
    if ( fd != -1) {
        read(fd, attr, 1024);
        sscanf((const char *)attr, "%lx", &phys_addr);
        close(fd);
    }
    return phys_addr;
}

// MARK: sync_for_cpu
double set_sync_for_cpu(int fd, unsigned long offset, unsigned long size){
    int status=0;

    if (fd != -1) {
        unsigned long sync_offset     = offset;
        unsigned long sync_size       = size;
        unsigned int  sync_direction  = 0;
        uint64_t      sync_for_cpu    = ((uint64_t)(sync_offset    & 0xFFFFFFFF) << 32) |
                                        ((uint64_t)(sync_size      & 0xFFFFFFF0) <<  0) |
                                        ((uint64_t)(sync_direction & 0x00000003) <<  2) |
                                        0x00000001; 
        status = ioctl(fd, U_DMA_BUF_IOCTL_SET_SYNC_FOR_CPU, &sync_for_cpu);
    }

    return status;
}

// MARK: sync_for_device
double set_sync_for_device(int fd, unsigned long offset, unsigned long size){
    int status=0;

    if (fd != -1) {
        unsigned long sync_offset     = offset;
        unsigned long sync_size       = size;
        unsigned int  sync_direction  = 0;
        uint64_t      sync_for_device = ((uint64_t)(sync_offset    & 0xFFFFFFFF) << 32) |
                                        ((uint64_t)(sync_size      & 0xFFFFFFF0) <<  0) |
                                        ((uint64_t)(sync_direction & 0x00000003) <<  2) |
                                        0x00000001;
        status = ioctl(fd, U_DMA_BUF_IOCTL_SET_SYNC_FOR_DEVICE, &sync_for_device);
    }

    return status;
}

// MARK: dgcpy_tx_cache
/* This function is used to copy data from u-dma-buf to user's buffer
 * u-dma-buf is opened without O_SYNC flag
 */
int dgcpy_tx_cache(BIO_BUF_DG *buffer, const char *data, int size){

    int space_left = buffer->max_size;
    int total_write = 0;
    int bytes_to_write = 0;
    int bytes_to_sync = 0;
    int remain_len = size;
    void *offset;
    uint32_t temp32b;

while( remain_len > 0 ){

    offset = (uint32_t *)( (uint64_t)(buffer->hw_base_addr) + ((off_t)(TLS_ALERT_REG) & (buffer->pagesize - 1)) );
    temp32b = *(volatile uint32_t *)offset ;

    if ( temp32b!=0 ) {
        ERR_raise(ERR_LIB_BIO, BIO_R_TRANSFER_ERROR);
        return -1;
    }

    // update pointer from hardware to software
    offset = (uint32_t *)( (uint64_t)(buffer->hw_base_addr) + ((off_t)(APP_TX_RDPTR_REG) & (buffer->pagesize - 1)) );
    buffer->tx_read_pos = ( *(volatile uint32_t *)offset ) & BUFFER_MASK; 

    // Calculate the space left for writing in the ring buffer
    space_left = (buffer->tx_read_pos - buffer->tx_write_pos - 1) & BUFFER_MASK;
    if (space_left == 0) {

        offset = (uint32_t *)( (uint64_t)(buffer->hw_base_addr) + ((off_t)(TLS_ALERT_REG) & (buffer->pagesize - 1)) );
        temp32b = *(volatile uint32_t *)offset ;

        if ( (temp32b&0xFF00)==0x0200 )
        {
            printf("\r\nAlertCode: 0x%04x\r\n",temp32b);
            ERR_raise(ERR_LIB_BIO, BIO_R_TRANSFER_ERROR);
            return -1;

        }
        // check connOn in case of no close-notify packet
        regRead(TOE_STS_INTREG, &temp32b);

        if ( (temp32b & TOE_STS_CONNON)==0 )
            return total_write;

    } else {
        // Determine the number of bytes to write
        bytes_to_write = (remain_len > space_left) ? space_left : remain_len;
        bytes_to_sync = bytes_to_write;

        if (buffer->tx_write_pos + bytes_to_write > buffer->max_size) {
            // Split the write into two parts
            size_t first_part = buffer->max_size - buffer->tx_write_pos;
            size_t second_part = bytes_to_write - first_part;

            memcpy(buffer->tx_buffer + buffer->tx_write_pos, data + total_write, first_part);
            bytes_to_sync = (first_part +15) & 0xFFFFFFF0;
            // bytes_to_sync = first_part;
            set_sync_for_device(buffer->tx_buffer_fd, (unsigned long)(buffer->tx_write_pos & 0xFFFFFFF0), (unsigned long)(bytes_to_sync));

            memcpy(buffer->tx_buffer, data + total_write + first_part, second_part);
            set_sync_for_device(buffer->tx_buffer_fd, 0, (unsigned long)( (second_part+15)&0xfffffff0 ) );
            buffer->tx_write_pos = second_part;  // Update the write position

        } else {
            memcpy(buffer->tx_buffer + buffer->tx_write_pos, data + total_write, bytes_to_write);
            bytes_to_sync = ( ( (buffer->tx_write_pos)&0xF ) + bytes_to_write +15) & 0xFFFFFFF0;
            set_sync_for_device(buffer->tx_buffer_fd, (unsigned long)(buffer->tx_write_pos & 0xFFFFFFF0), (unsigned long)(bytes_to_sync));

            buffer->tx_write_pos = (buffer->tx_write_pos + bytes_to_write) & BUFFER_MASK;  // Update the write position
        }

        // Update write pointer to hardware
        offset = (uint32_t *)( (uint64_t)(buffer->hw_base_addr) + ((off_t)(APP_TX_WRPTR_REG) & (buffer->pagesize - 1)) );
        *(volatile uint32_t *)offset = buffer->tx_write_pos;

        total_write = total_write + bytes_to_write;
        remain_len = remain_len - bytes_to_write;
    }
}
    return total_write;
}

// MARK: dgcpy_rx_cache
/* This function is used to copy data from user's buffer to u-dma-buf
 * u-dma-buf is opened without O_SYNC flag => with cache
 */
int dgcpy_rx_cache(BIO_BUF_DG *buffer, char *data, int size){
    
    int     available_data = 0;
    int     available_ddr_data = 0;
    int     total_read    = 0;
    int     bytes_to_read = 0;
    int     remain_len    = size;
    struct  timespec start_timestamp, current_timestamp;
    uint32_t temp32b;
    void *offset;

    // stamp time
    clock_gettime(CLOCK_MONOTONIC, &start_timestamp);

    while ( remain_len > 0 ){

        // Calculate the size of available data for reading from the ring buffer
        available_data = (buffer->rx_write_pos - buffer->rx_read_pos) & BUFFER_MASK;

        if (available_data <= 0) {
            clock_gettime(CLOCK_MONOTONIC, &current_timestamp);
            
            // check available data in DDR
            offset = (uint32_t *)( (uint64_t)(buffer->hw_base_addr) + ((off_t)(APP_RX_WRPTR_REG) & (buffer->pagesize - 1)) );
            buffer->rx_ddr_wr_pos = ( *(volatile uint32_t *)offset ) & BUFFER_MASK;

            available_ddr_data = (buffer->rx_ddr_wr_pos - buffer->rx_write_pos) & BUFFER_MASK;

            if (available_ddr_data <=0) {
                offset = (uint32_t *)( (uint64_t)(buffer->hw_base_addr) + ((off_t)(TLS_ALERT_REG) & (buffer->pagesize - 1)) );
                temp32b = *(volatile uint32_t *)offset ;

                if ( (temp32b&0xFF00)==0x0200 )
                {
                    printf("\r\nAlertCode: 0x%04x\r\n",temp32b);
                    ERR_raise(ERR_LIB_BIO, BIO_R_TRANSFER_ERROR);
                    return -1;

                } else if ( temp32b==0x0100 ) {
                    return total_read;
                }

                // check connOn in case of no close-notify packet
                regRead(TOE_STS_INTREG, &temp32b);

                if ( (temp32b & TOE_STS_CONNON)==0 )
                    return total_read;

            } else {
                // if there are available data more than 75% of Host buffer size, then update cache for the whole page
                if ( (available_ddr_data & 0x000C0000)==0x000C0000 ) {
                    set_sync_for_cpu(buffer->rx_buffer_fd, (unsigned long)(0), (unsigned long)(DG_BUFFER_SIZE) );
                    buffer->rx_write_pos = buffer->rx_ddr_wr_pos;
                } 
                // check whether cross page
                else if ( (buffer->rx_write_pos + available_ddr_data) > buffer->max_size ) {
                    // sync until the end of page
                    available_ddr_data = buffer->max_size - (buffer->rx_write_pos & 0xFFFFFFF0);
                    set_sync_for_cpu(buffer->rx_buffer_fd, (unsigned long)(buffer->rx_write_pos & 0xFFFFFFF0), (unsigned long)(available_ddr_data) );
                    buffer->rx_write_pos = 0;
                } else {
                    set_sync_for_cpu(buffer->rx_buffer_fd, (unsigned long)(buffer->rx_write_pos & 0xFFFFFFF0), (unsigned long)((available_ddr_data+15) & 0xFFFFFFF0) );
                    buffer->rx_write_pos = (buffer->rx_write_pos + available_ddr_data) & BUFFER_MASK;
                }
            }

        } else {
            // Determine the number of bytes to read
            // bytes_to_read = (size > available_data) ? available_data : size;
            bytes_to_read = (remain_len > available_data) ? available_data : remain_len;
            
            if ( (buffer->rx_read_pos + bytes_to_read) > buffer->max_size) {
                // Split the read into two parts
                size_t first_part = buffer->max_size - buffer->rx_read_pos;
                size_t second_part = bytes_to_read - first_part;

                memcpy(data + total_read, buffer->rx_buffer + buffer->rx_read_pos, first_part);
                memcpy(data + total_read + first_part, buffer->rx_buffer, second_part);

                buffer->rx_read_pos = second_part;  // Update the read position
            } else {
                
                memcpy(data + total_read, buffer->rx_buffer + buffer->rx_read_pos, bytes_to_read);
                buffer->rx_read_pos = (buffer->rx_read_pos + bytes_to_read) & BUFFER_MASK;  // Update the read position
            }

            // Update read pointer to hardware
            offset = (uint32_t *)( (uint64_t)(buffer->hw_base_addr) + ((off_t)(APP_RX_RDPTR_REG) & (buffer->pagesize - 1)) );
            *(volatile uint32_t *)offset = buffer->rx_read_pos;

            total_read = total_read + bytes_to_read;
            remain_len = size - total_read;
        }
    }

    return total_read;
}
