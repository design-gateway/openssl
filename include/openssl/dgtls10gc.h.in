#ifndef DGTLS10GC_H
#define DGTLS10GC_H

#ifdef  __cplusplus
extern "C" {
#endif
        #include <stdio.h>
        #include <stdint.h>
        #include <string.h>
        #include <inttypes.h>
        #include <openssl/bio.h>
        #include <unistd.h>
        #include <stdlib.h>
        #include <errno.h>
        #include <sys/mman.h>
        #include <termios.h>
        #include <fcntl.h>
        #include <sys/ioctl.h>

        typedef struct {
            int tx_buffer_fd;
            char *tx_buffer;
            int tx_read_pos;
            int tx_write_pos;
            int tx_seq_num_H;
            int tx_seq_num_L;

            int rx_buffer_fd;
            char *rx_buffer;
            int rx_read_pos;
            int rx_write_pos;
            int rx_ddr_wr_pos;
            int rx_seq_num_H;
            int rx_seq_num_L;

            int max_size;
            long pagesize;
            void *hw_base_addr;
        } BIO_BUF_DG;

        // Define a structure to hold DG BIO data
        #define PAGE_SIZE       (2 * 1024 * 1024) // page_size = 2MB;
        #define DG_BUFFER_SIZE  (1 * 1024 * 1024) //0x100000
        #define BUFFER_MASK     0x00FFFFF

        #define DG_SW_TMO           5               // in second(s)

        #define BASE_ADDR           0xA0000000
        #define TOE_BASE_ADDR       0xA0080000
        #define BASE_ADDR_REG       (uint32_t*)(BASE_ADDR)

        #define TOE_STS_INTREG      (uint32_t*)(TOE_BASE_ADDR+0x0044)   // TOE10GLL-IP Control and Connection status 
        #define TOE_STS_CONNON      0x00000002

        // TLS10GIP control signal
        #define TLS_RSTB_REG        (uint32_t*)(BASE_ADDR+0x0000)
        #define TLS_BUSY_REG        (uint32_t*)(BASE_ADDR+0x0004)
        #define TLS_ALERT_REG       (uint32_t*)(BASE_ADDR+0x0008)
        #define TLS_TIMEOUT_REG     (uint32_t*)(BASE_ADDR+0x000C)

        #define TLS_MODESET_REG     (uint32_t*)(BASE_ADDR+0x0010)
        #define TLS_PHASE_REG       (uint32_t*)(BASE_ADDR+0x0014)
        #define CTS_IN_VALID_REG    (uint32_t*)(BASE_ADDR+0x0018)
        #define STS_IN_VALID_REG    (uint32_t*)(BASE_ADDR+0x001C)

        #define CTS_IN_REG          (uint32_t*)(BASE_ADDR+0x0020)
        #define STS_IN_REG          (uint32_t*)(BASE_ADDR+0x0050)

        #define TX_SEQNUM_0_REG     (uint32_t*)(BASE_ADDR+0x0080)
        #define TX_SEQNUM_1_REG     (uint32_t*)(BASE_ADDR+0x0084)
        #define RX_SEQNUM_0_REG     (uint32_t*)(BASE_ADDR+0x0088)
        #define RX_SEQNUM_1_REG     (uint32_t*)(BASE_ADDR+0x008C)

        // DMA control logic
        #define TLS_TX_RDPTR_REG    (uint32_t*)(BASE_ADDR+0x0100)
        #define TLS_TX_WRPTR_REG    (uint32_t*)(BASE_ADDR+0x0104)
        #define TLS_RX_RDPTR_REG    (uint32_t*)(BASE_ADDR+0x0108)
        #define TLS_RX_WRPTR_REG    (uint32_t*)(BASE_ADDR+0x010C)
        
        #define APP_TX_RDPTR_REG    (uint32_t*)(BASE_ADDR+0x0110)
        #define APP_TX_WRPTR_REG    (uint32_t*)(BASE_ADDR+0x0114)
        #define APP_RX_RDPTR_REG    (uint32_t*)(BASE_ADDR+0x0118)
        #define APP_RX_WRPTR_REG    (uint32_t*)(BASE_ADDR+0x011C)

        #define SET_DMA_DST_H_ADDR  (uint32_t*)(BASE_ADDR+0x0120)
        #define SET_DMA_DST_L_ADDR  (uint32_t*)(BASE_ADDR+0x0124)
        #define SET_DMA_SRC_H_ADDR  (uint32_t*)(BASE_ADDR+0x0128)
        #define SET_DMA_SRC_L_ADDR  (uint32_t*)(BASE_ADDR+0x012C)
        #define DMA_STATUS_REG      (uint32_t*)(BASE_ADDR+0x0130)

        int splitStr(char *str, char *arrStr[], char splitter);

        uint32_t* string_to_uint32_array(const char* str, size_t *out_size);

        void dg_keylog_callback(const SSL *ssl, const char *line);
        void dg_ssl_info_callback(const SSL *s, int where, int ret);

        // Function to read from a memory-mapped address
        uint32_t regRead(uint32_t * mem_ptr, uint32_t * value);
        // Function to write to a memory-mapped address
        uint32_t regWrite(uint32_t * mem_ptr, uint32_t value);

        // // Get Physical address from virtual address
        uint64_t get_phys_addr(const char *devicefilename);

        const char* errno_to_name(int errnum);

        double set_sync_for_cpu(int fd, unsigned long offset, unsigned long size);
        double set_sync_for_device(int fd, unsigned long offset, unsigned long size);

        int dgcpy_tx_cache(BIO_BUF_DG *buffer, const char *data, int size);
        int dgcpy_rx_cache(BIO_BUF_DG *buffer, char *data, int size);

# ifdef  __cplusplus
}
# endif

#endif // DGTLS10GC_H

/*********************************************************************************
 *
 *       Copyright (C) 2015-2024 Ichiro Kawazome
 *       All rights reserved.
 * 
 *       Redistribution and use in source and binary forms, with or without
 *       modification, are permitted provided that the following conditions
 *       are met:
 * 
 *         1. Redistributions of source code must retain the above copyright
 *            notice, this list of conditions and the following disclaimer.
 * 
 *         2. Redistributions in binary form must reproduce the above copyright
 *            notice, this list of conditions and the following disclaimer in
 *            the documentation and/or other materials provided with the
 *            distribution.
 * 
 *       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *       A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 *       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 *       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 ********************************************************************************/
#ifndef  U_DMA_BUF_IOCTL_H
#define  U_DMA_BUF_IOCTL_H
#include <linux/ioctl.h>

#define DEFINE_U_DMA_BUF_IOCTL_FLAGS(name,type,lo,hi)                     \
static const  int      U_DMA_BUF_IOCTL_FLAGS_ ## name ## _SHIFT = (lo);   \
static const  uint64_t U_DMA_BUF_IOCTL_FLAGS_ ## name ## _MASK  = (((uint64_t)1UL << ((hi)-(lo)+1))-1); \
static inline void SET_U_DMA_BUF_IOCTL_FLAGS_ ## name(type *p, int value) \
{                                                                         \
    const int      shift = U_DMA_BUF_IOCTL_FLAGS_ ## name ## _SHIFT;      \
    const uint64_t mask  = U_DMA_BUF_IOCTL_FLAGS_ ## name ## _MASK;       \
    p->flags &= ~(mask << shift);                                         \
    p->flags |= ((value & mask) << shift);                                \
}                                                                         \
static inline int  GET_U_DMA_BUF_IOCTL_FLAGS_ ## name(type *p)            \
{                                                                         \
    const int      shift = U_DMA_BUF_IOCTL_FLAGS_ ## name ## _SHIFT;      \
    const uint64_t mask  = U_DMA_BUF_IOCTL_FLAGS_ ## name ## _MASK;       \
    return (int)((p->flags >> shift) & mask);                             \
}

typedef struct {
    uint64_t flags;
    char     version[16];
} u_dma_buf_ioctl_drv_info;

DEFINE_U_DMA_BUF_IOCTL_FLAGS(IOCTL_VERSION      , u_dma_buf_ioctl_drv_info ,  0,  7)
DEFINE_U_DMA_BUF_IOCTL_FLAGS(IN_KERNEL_FUNCTIONS, u_dma_buf_ioctl_drv_info ,  8,  8)
DEFINE_U_DMA_BUF_IOCTL_FLAGS(USE_OF_DMA_CONFIG  , u_dma_buf_ioctl_drv_info , 12, 12)
DEFINE_U_DMA_BUF_IOCTL_FLAGS(USE_OF_RESERVED_MEM, u_dma_buf_ioctl_drv_info , 13, 13)
DEFINE_U_DMA_BUF_IOCTL_FLAGS(USE_QUIRK_MMAP     , u_dma_buf_ioctl_drv_info , 16, 16)
DEFINE_U_DMA_BUF_IOCTL_FLAGS(USE_QUIRK_MMAP_PAGE, u_dma_buf_ioctl_drv_info , 17, 17)

typedef struct {
    uint64_t flags;
    uint64_t size;
    uint64_t addr;
} u_dma_buf_ioctl_dev_info;

DEFINE_U_DMA_BUF_IOCTL_FLAGS(DMA_MASK    , u_dma_buf_ioctl_dev_info ,  0,  7)
DEFINE_U_DMA_BUF_IOCTL_FLAGS(DMA_COHERENT, u_dma_buf_ioctl_dev_info ,  9,  9)
DEFINE_U_DMA_BUF_IOCTL_FLAGS(MMAP_MODE   , u_dma_buf_ioctl_dev_info , 10, 12)

typedef struct {
    uint64_t flags;
    uint64_t size;
    uint64_t offset;
} u_dma_buf_ioctl_sync_args;

DEFINE_U_DMA_BUF_IOCTL_FLAGS(SYNC_CMD    , u_dma_buf_ioctl_sync_args,  0,  1)
DEFINE_U_DMA_BUF_IOCTL_FLAGS(SYNC_DIR    , u_dma_buf_ioctl_sync_args,  2,  3)
DEFINE_U_DMA_BUF_IOCTL_FLAGS(SYNC_MODE   , u_dma_buf_ioctl_sync_args,  8, 15)
DEFINE_U_DMA_BUF_IOCTL_FLAGS(SYNC_OWNER  , u_dma_buf_ioctl_sync_args, 16, 16)

enum {
    U_DMA_BUF_IOCTL_FLAGS_SYNC_CMD_FOR_CPU    = 1,
    U_DMA_BUF_IOCTL_FLAGS_SYNC_CMD_FOR_DEVICE = 3
};

typedef struct {
    uint64_t flags;
    uint64_t size;
    uint64_t offset;
    uint64_t addr;
    int      fd;
} u_dma_buf_ioctl_export_args;

DEFINE_U_DMA_BUF_IOCTL_FLAGS(EXPORT_FD_FLAGS, u_dma_buf_ioctl_export_args,  0, 31)

#define U_DMA_BUF_IOCTL_MAGIC               'U'
#define U_DMA_BUF_IOCTL_GET_DRV_INFO        _IOR (U_DMA_BUF_IOCTL_MAGIC, 1, u_dma_buf_ioctl_drv_info)
#define U_DMA_BUF_IOCTL_GET_SIZE            _IOR (U_DMA_BUF_IOCTL_MAGIC, 2, uint64_t)
#define U_DMA_BUF_IOCTL_GET_DMA_ADDR        _IOR (U_DMA_BUF_IOCTL_MAGIC, 3, uint64_t)
#define U_DMA_BUF_IOCTL_GET_SYNC_OWNER      _IOR (U_DMA_BUF_IOCTL_MAGIC, 4, uint32_t)
#define U_DMA_BUF_IOCTL_SET_SYNC_FOR_CPU    _IOW (U_DMA_BUF_IOCTL_MAGIC, 5, uint64_t)
#define U_DMA_BUF_IOCTL_SET_SYNC_FOR_DEVICE _IOW (U_DMA_BUF_IOCTL_MAGIC, 6, uint64_t)
#define U_DMA_BUF_IOCTL_GET_DEV_INFO        _IOR (U_DMA_BUF_IOCTL_MAGIC, 7, u_dma_buf_ioctl_dev_info)
#define U_DMA_BUF_IOCTL_GET_SYNC            _IOR (U_DMA_BUF_IOCTL_MAGIC, 8, u_dma_buf_ioctl_sync_args)
#define U_DMA_BUF_IOCTL_SET_SYNC            _IOW (U_DMA_BUF_IOCTL_MAGIC, 9, u_dma_buf_ioctl_sync_args)
#define U_DMA_BUF_IOCTL_EXPORT              _IOWR(U_DMA_BUF_IOCTL_MAGIC,10, u_dma_buf_ioctl_export_args)
#endif /* #ifndef U_DMA_BUF_IOCTL_H */
