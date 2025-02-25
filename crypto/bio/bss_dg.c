#include <stdio.h>
#include <errno.h>
#include "crypto/bio/bio_local.h"
#include "internal/cryptlib.h"
#include "openssl/dgtls10gc.h"
#include <time.h>

#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// Function prototypes
static int dg_bio_write(BIO *b, const char *buf, int len);
static int dg_bio_read(BIO *b, char *buf, int len);
static int dg_bio_puts(BIO *b, const char *str);
static int dg_bio_gets(BIO *b, char *buf, int size);
static long dg_bio_ctrl(BIO *b, int cmd, long num, void *ptr);
static int dg_bio_new(BIO *b);
static int dg_bio_free(BIO *b);

static const BIO_METHOD dg_bio_method = {
    BIO_TYPE_DG,
    "DG BIO",
    bwrite_conv,
    dg_bio_write,
    bread_conv,
    dg_bio_read,
    dg_bio_puts,
    dg_bio_gets,
    dg_bio_ctrl,
    dg_bio_new,
    dg_bio_free,
    NULL,         
};

const BIO_METHOD *BIO_s_DG(void)
{
    return &dg_bio_method;
}

// MARK: dg_bio_new
static int dg_bio_new(BIO *b)
{
    BIO_BUF_DG *buffer = (BIO_BUF_DG *)malloc(sizeof(BIO_BUF_DG));
    if (buffer == NULL) {
        return 0;
    }

    char *HostTx = NULL;
    char *HostRx = NULL;

    // -- Tx --
    const char *device0 = "/dev/udmabuf0";
    // Check if the device0 exists
    if (access(device0, F_OK) != 0) {
        printf("Device0 '%s' not exists.\r\n", device0);
        return 0;
    }

    int tx_buffer_fd  = open("/dev/udmabuf0", O_RDWR);
    if (tx_buffer_fd == -1) {
        perror("open /dev/udmabuf0 failed");
        return 0;
    }

    HostTx = (char *)mmap(NULL, DG_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED , tx_buffer_fd, 0);
    if (HostTx == MAP_FAILED) {
        perror("mmap");
        printf("HostTx failed: %s\r\n", errno_to_name(errno));
        return 0;
    }

    // -- Rx --
    const char *device1 = "/dev/udmabuf1";
    // Check if the device1 exists
    if (access(device1, F_OK) != 0) {
        printf("Device1 '%s' not exists.\r\n", device1);
        return 0;
    } 

    int rx_buffer_fd  = open("/dev/udmabuf1", O_RDWR);
    if (rx_buffer_fd == -1) {
        perror("open /dev/udmabuf1 failed");
        return 0;
    }

    HostRx = (char *)mmap(NULL, DG_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED , rx_buffer_fd, 0);
    if (HostTx == MAP_FAILED) {
        perror("mmap");
        printf("HostTx failed: %s\n", errno_to_name(errno));
        return 0;
    }

    // open dev/mem to access hardware registers
    off_t addr = (off_t)BASE_ADDR_REG;

    // Get the page size
    long pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize <= 0) {
        perror("sysconf");
        return -1;
    }
    // Open /dev/mem
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem failed");
        return -1;
    }
    // Memory map the specified address with read and write permissions
    void *base;
    base = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, addr & ~(pagesize - 1));
    if (base == MAP_FAILED) {
        perror("mmap failed bss_dg");
        close(mem_fd); // Close the file descriptor before returning
        return -1;
    }

    // initial BIO_s_DG
    buffer->max_size = DG_BUFFER_SIZE;
    // buffer->flags = 0;
    buffer->pagesize = pagesize;
    buffer->hw_base_addr = base;
    // tx
    buffer->tx_buffer_fd = tx_buffer_fd; 
    buffer->tx_buffer = HostTx;
    buffer->tx_read_pos  = 0;
    buffer->tx_write_pos = 0;
    buffer->tx_seq_num_H = 0;
    buffer->tx_seq_num_L = 0;
    // rx
    buffer->rx_buffer_fd = rx_buffer_fd;
    buffer->rx_buffer = HostRx;
    buffer->rx_read_pos  = 0;
    buffer->rx_write_pos = 0;
    buffer->rx_ddr_wr_pos = 0;
    buffer->rx_seq_num_H = 0;
    buffer->rx_seq_num_L = 0;

    BIO_set_data(b, buffer);
    BIO_set_init(b, 1);

    // initialize hardware parameters
    // set physical address
    // Tx
    uint64_t physical_source_address = get_phys_addr("/sys/class/u-dma-buf/udmabuf0/phys_addr");
    uint32_t mm2s_lower_32_bits = (uint32_t)(physical_source_address & 0xFFFFFFFF);
    uint32_t mm2s_upper_32_bits = (uint32_t)((physical_source_address >> 32) & 0xFFFFFFFF);
    // Rx
    uint64_t physical_destination_address = get_phys_addr("/sys/class/u-dma-buf/udmabuf1/phys_addr");
    uint32_t ss2m_lower_32_bits = (uint32_t)(physical_destination_address & 0xFFFFFFFF);
    uint32_t ss2m_upper_32_bits = (uint32_t)((physical_destination_address >> 32) & 0xFFFFFFFF);

    // initial DMA parameters
    regWrite(DMA_STATUS_REG, 1);
    // set physical address
    // Tx
    regWrite(SET_DMA_SRC_H_ADDR, mm2s_upper_32_bits);
    regWrite(SET_DMA_SRC_L_ADDR, mm2s_lower_32_bits);
    regWrite(APP_TX_RDPTR_REG, mm2s_lower_32_bits);
    regWrite(APP_TX_WRPTR_REG, mm2s_lower_32_bits);
    uint32_t temp32b;   // clear remaining Tx data from the previous connection
    regRead(TLS_TX_RDPTR_REG, &temp32b);
    regWrite(TLS_TX_WRPTR_REG, temp32b);
    // RX
    regWrite(SET_DMA_DST_H_ADDR, ss2m_upper_32_bits);
    regWrite(SET_DMA_DST_L_ADDR, ss2m_lower_32_bits);
    regWrite(APP_RX_RDPTR_REG, ss2m_lower_32_bits);
    regWrite(APP_RX_WRPTR_REG, ss2m_lower_32_bits);
    // release reset
    regWrite(DMA_STATUS_REG, 0);
    return 1;
}

// MARK: dg_bio_free
static int dg_bio_free(BIO *b)
{
    if (b == NULL) {
        return 0;
    }
    BIO_set_data(b, NULL);
    return 0;
}

// MARK: dg_bio_write
static int dg_bio_write(BIO *b, const char *data, int size)
{
    BIO_BUF_DG *buffer = (BIO_BUF_DG *)BIO_get_data(b);
    
    if (buffer == NULL || data == NULL || size <= 0) {
        printf("\r\ncannot write to BIO_s_DG\r\n");
        return 0;
    } else {
        BIO_clear_retry_flags(b);
    }

    int bytes_to_write = dgcpy_tx_cache(buffer, data, size);

    BIO_clear_retry_flags(b);
    if (bytes_to_write <= 0) {
        if (BIO_sock_should_retry(bytes_to_write))
            BIO_set_retry_write(b);
    }

    return bytes_to_write;
}

// MARK: dg_bio_read
static int dg_bio_read(BIO *b, char *data, int size)
{
    int ret = 0;
    BIO_BUF_DG *buffer = (BIO_BUF_DG *)BIO_get_data(b);
    if (buffer == NULL || data == NULL) {
        printf("\r\ncannot read from BIO_s_DG\r\n");
        return 0;
    }
    ret = dgcpy_rx_cache(buffer, data, size);
    if (ret == 0)
        b->flags |= BIO_FLAGS_IN_EOF;

    return ret;
}

static int dg_bio_puts(BIO *b, const char *str)
{
    return dg_bio_write(b, str, strlen(str));
}

static int dg_bio_gets(BIO *b, char *buf, int size)
{
    return dg_bio_read(b, buf, size);
}

// MARK: dg_bio_ctrl
static long dg_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    switch (cmd) {
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;
        case BIO_CTRL_EOF:
            ret = (b->flags & BIO_FLAGS_IN_EOF) != 0;
            break;
        default:
            ret = 0;
            break;
    }
    return ret;
}