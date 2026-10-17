# 内存分配典型性优化：

目前发现生产环境中的内存分配释放还是很有规律的，都是通过宏定义指向另外的宏定义或者函数定义。
从观测到的nlog和nat来看，最常用的配对宏/函数有：
1. VOS_Malloc_F/VOS_Free_F # 第三方的宏定义
2. HpeMemAlloc/HpeMemFree # 第三方的宏定义
3. malloc/free #函数定义，一般用于本地单元测试
4. VOS_Mem_Allock_F/VOS_MemFree_F  # 第三方的宏定义
5. VOS_Mem_ReAllock_F/VOS_MemFree_F # 第三方的宏定义

之所以会封装成宏或者函数。
* 封装成自己的函数：是为了分配后进行判空处理同时调用memset_s初始化以后再返回指针，这样可以避免很多空指针异常和数据泄露问题。项目中还很常见。
* 封装成宏：则是直接调用第三方宏，例如：VOS_Malloc_F宏，就直调用的其他团队的内存分配函数，这样可以保证内存分配的统一性，避免出现内存泄漏问题。

下面列举两个仓库的封装（我又40+个仓库），每个仓库都自己起了名字，但是功能基本上就是上面描述的5个总结场景。

## nlog仓库：

#if defined(CONFIG_FW_SYS) || defined(CONFIG_FW_LLT)
#define nlog_malloc(mid, size) malloc((size))
#define nlog_free free
#elif defined CONFIG_FW_VM
#include "vrp_mem.h"
#define nlog_malloc(mid, size)    VOS_Malloc_F(mid, size, __FILE__, __LINE__)
#define nlog_free(ptr)            VOS_Free_F(ptr, __FILE__, __LINE__)
#elif defined CONFIG_FW_FWD
#include "dataplane/adapt/nlog_dp_mem.h"
#define nlog_malloc(mid, size) NLOG_DP_MALLOC(size)
#define nlog_free NLOG_DP_FREE
#else
#include "ctrlplane/init/nlog_mem_init.h"
#define nlog_malloc(mid, size) nlog_malloc_f(mid, size, __FUNCTION__, __LINE__)
#define nlog_realloc(mid, ptr, size) nlog_realloc_f(mid, ptr, size, __FUNCTION__, __LINE__)
#define nlog_free(p) nlog_free_f(p, __FUNCTION__, __LINE__)
#endif

## nat仓库：
#ifdef CONFIG_FW_FPATH
#define NAT_TLB __thread
#else
#define NAT_TLB
#endif

#if defined(CONFIG_FW_VM)
#include "vrp_mem.h"
#define NAT_MALLOC(mid, size) VOS_Malloc_F(mid, size, __FILE__, __LINE__)
#define NAT_FREE(buf) (void)VOS_Free_F(buf, __FILE__, __LINE__)
#elif defined(CONFIG_FW_FPATH)
#include <stdlib.h>
#include "hpe_mem.h"
#include "hpe_mod.h"
DECLARE_MOD(mod_nat);
#define NAT_MALLOC(mid, size) HpeMemAlloc(MOD_ID(mod_nat), HPE_HEAP_MEM, size, 0)
#define NAT_FREE(buf) HpeMemFree(buf)
#else
#include <stdlib.h>
#define NAT_MALLOC(mid, size) malloc(size)
#define NAT_FREE(buf) free(buf)
#endif