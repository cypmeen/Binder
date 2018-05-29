## 欢迎和我一起走进Android Binder机制

**Binder**机制是Android的一高阶核心机制。

文章一开始，我想问自己或问大家几个问题，我相信带着问题进入深究才是得大成者之风范。
- 何为Binder？
- Binder在Android系统起一个什么样的角色?
- Android为什么选择Binder?

> 关于Binder在Android的应用大家请参考 [开发者文档](https://developer.android.com/guide/components/bound-services?hl=zh-CN)

在Android系统中，每一个应用程序都是由一些Activity和Service组成的，一般Service运行在独立的进程中，而Activity可能运行在同一个进程中，也有可能运行在不同的进程中。众所周知，Android系统是基于Linux内核的，而Linux内核继承和兼容了丰富的Unix系统进程间通信（IPC）机制。有传统的管道（Pipe）、信号（Signal）和跟踪（Trace），这三项通信手段只能用于父进程和子进程之间，或者只用于兄弟进程之间。随着技术的发展，后来又增加了命令管道（Named Pipe），这样使得进程之间的通信不再局限于父子进程或者兄弟进程之间。为了更好地支持商业应用中的事务处理，在AT&T的Unix系统V中，又增加了如下3种称为“System V IPC”的进程间通信机制。

- 报文队列
- 共享内存
- 信号量

    Android系统没有采用上述提到的各种进程间通信机制,而是采用Binder机制。　其实Binder并不是Android提出来的一套新的进程间通信机制,它是基于OpenBinder来实现的。Binder是一种进程间通信机制，其类似于COM和CORBA分布式组件架构。具体来说，其实是提供了远程过程调用（RPC）功能。

    在Android系统中，Binder机制由Client、Server、Service Manager和Binder驱动程序等一系统组件组成。其中Client、Server和Service Manager运行在用户空间，Binder驱动程序运行在内核空间，Binder就是一种把这4个组件黏合在一起的黏结剂。在上述Binder组件中，核心组件是Binder驱动程序。Service Manager提供了辅助管理的功能，Client和Server正是在Binder驱动和Service Manager提供的基础设施上实现Client/Server之间通信功能的。Service Manager和Binder驱动已经在Android平台中实现完毕，开发者只要按照规范实现自己的Client和Server组件即可。

### 何为RPC?
<p>
    RPC是指远程过程调用，也就是说两台服务器A,B,一个应用部署在A服务器上,想要调用B服务器上应用提供的函数/方法，由于不再一个内存空间，不能直接调用，需要通过网络来表达调用的语义和传达调用的数据。　
</p>

![RPC过程图](http://chuantu.biz/t6/320/1527475510x-1404764888.jpg)

说实话，Android系统的Binder机制比较难以理解,而Bidner机制无论从系统开发还是应用开发的角度来看，都是Android系统中最重要的组成，所以很有必要深入了解Binder的工作方式，最好的方式还是阅读Binder相关的Fucking Code。

### 进入Binder系统
    要想深入理解Binder机制，必须了解Binder在用户空间的3个组件Client、Server和Service Manager之间的相互关系，并了解内核空间中Binder驱动程序的数据结构和设计原理。具体来说，Android系统Binder机制中的4个组件Client、Server、Service Manager和Binder驱动程序的关系,如图。
![组件Client、Server、Service Manager和Binder驱动程序的关系](http://chuantu.biz/t6/320/1527477094x-1566657549.png)

上图所示关系的具体说明如下:

-（1）Client、Server和Service Manager实现在用户空间中，Binder驱动程序实现在内核空间中。

-（2）Binder驱动程序和Service Manager在Android平台中已经实现，开发者只需要在用户空间实现自己的Client和Server。

-（3）Binder驱动程序提供设备文件“/dev/binder“与用户空间交互，Client、Server和Service Manager通过文件操作函数open()和ioctl()与Binder驱动程序进行通信。

-（4）Client和Server之间的进程间通信通过Binder驱动程序间接实现。

-（5）Service Manager是一个保护进程，用来管理Server，并向Client提供查询Server接口的能力。

## 进入Fucking Code 之 ServiceManager
> 进入之前先带着问题，ServiceManager在整个Binder机制中是处于什么角色?它是如何协调Server、Client和Binder内核驱动之间的关系的?

在Android系统中，Service Manager负责告知Binder驱动程序它是Binder机制的上下文管理者。Service Manager是整个Binder机制的保护进程，用来管理开发者创建的各种Server，并且向Client提供查询Server远程接口的功能。

因为Service Manager组件是用来管理Server并且向Client提供查询Server远程接口的功能，所以Service Manager必然要和Server以及Client进行通信。Service Manger、Client和Server三者分别是运行在独立的进程当中的，这样它们之间的通信也属于进程间的通信，而且也是采用Binder机制进行进程间通信。因此，Service Manager在充当Binder机制的保护进程的角色的同时也在充当Server的角色，也是一种特殊的Server。

Service Manager在用户空间的源代码位于“frameworks/base/cmds/servicemanager”目录下，主要是由文件binder.h、binder.c和service_manager.c组成。Service Manager在Binder机制中的基本执行流程如下图所示。

![Service Manager在Binder机制中的基本执行流程](http://chuantu.biz/t6/320/1527494412x-1566657549.png)

ServiceManager的入口于文件service_manager.c中，主函数main的实现代码如下所示:

```c
int main(int argc, char **argv)
{
    struct binder_state *bs;
    void *svcmgr = BINDER_SERVICE_MANAGER;
    bs = binder_open(128*1024);
    if (binder_become_contect_manager(bs)) {
        ALOGE("cannot become context manager (%s)\n", strerror(errno));
        return -1;
    }
    svcmgr_handle = svcmgr;
    binder_loop(bs, svcmgr_handler);
    return 0; 
}
```
上述函数main()主要有以下３个功能。

- 打开Binder设备文件。
- 告诉Binder驱动程序自己是Binder上下文管理者，即前面所说的保护进程。
- 进入一个无穷循环，充当Server的角色，等待Client的请求。

在分析上述3个功能之前，先来看一下这里用到的结构体binder_state、宏BINDER_SERVICE_MANAGER的定义。结构体binder_state在文件frameworks/base/cmds/servicemanager/binder.c中定义，代码如下所示：

```c
struct binder_state {
    int fd;  // 文件描述符
    void *mapped; // /dev/binder设备内存信息的起始地址
    unsigned mapsize; // 内存映射空间的大小
};
```
其中fd表示文件描述符，即表示打开的“/dev/binder”设备文件描述符；mapped表示把设备文件“/dev/binder”映射到进程空间的起始地址；mapsize表示上述内存映射空间的大小。

宏BINDER_SERVICE_MANAGER在文件frameworks/base/cmds/servicemanager/binder.h中定义，代码如下所示：

```c
/* 这个宏定义我也不知道什么意思,没有任何赋值的地方在代码中 */
#define BINDER_SERVICE_MANAGER ((void*) 0)
```
**查阅先关资料说这个表示的是Service Manager的句柄为０，Binder通信机制使用句柄来代表远程接口。我们现在暂时认定这个定义是代表远程接口句柄。**

#### 解析binder_open函数
在binder.h中找到定义，它是打开Binder设备文件的操作函数，代码如下:

```c
    struct binder_state *binder_open(unsigned mapsize){
    struct binder_state *bs;
    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return 0;
    }
    bs->fd = open("/dev/binder", O_RDWR);
    if (bs->fd < 0) {
        fprintf(stderr,"binder: cannot open device (%s)\n",
                strerror(errno));
        goto fail_open;
    }
    bs->mapsize = mapsize;
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        fprintf(stderr,"binder: cannot map device (%s)\n",
                strerror(errno));
        goto fail_map;
    }
        /* TODO: check version */
    return bs;
fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return 0;
}
```
通过文件操作函数open()打开设备文件“/dev/binder”，此设备文件是在Binder驱动程序模块初始化的时候创建的。接下来先看一下这个设备文件的创建过程，来到<br/>kernel/common/drivers/ staging/android目录，打开文件binder.c，可以看到如下模块初始化入口binder_init：

```c
    static struct file_operations binder_fops = {
    .owner = THIS_MODULE,
    .poll = binder_poll,
    .unlocked_ioctl = binder_ioctl,
    .mmap = binder_mmap,
    .open = binder_open,
    .flush = binder_flush,
    .release = binder_release,
};
    static struct miscdevice binder_miscdev = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "binder",
        .fops = &binder_fops
    };
    static int __init binder_init(void)
    {
        int ret;
        binder_proc_dir_entry_root = proc_mkdir("binder", NULL);
        if (binder_proc_dir_entry_root)
            binder_proc_dir_entry_proc = proc_mkdir("proc", binder_proc_dir_entry_root);
        ret = misc_register(&binder_miscdev);
        if (binder_proc_dir_entry_root) {
            create_proc_read_entry("state", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_state, NULL);
            create_proc_read_entry("stats", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_stats, NULL);
            create_proc_read_entry("transactions", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_transactions, NULL);
            create_proc_read_entry("transaction_log", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_transaction_log, &binder_transaction_log);
            create_proc_read_entry("failed_transaction_log", S_IRUGO,binder_proc_dir_entry_root,binder_read_proc_transaction_log, &binder_transaction_log_failed);             
        }
    return ret;
}

device_initcall(binder_init);

```

在函数misc_register()中实现了创建设备文件的功能，并实现了misc设备的注册工作，在“/proc”目录中创建了各种Binder相关的文件供用户访问。通过如下函数binder_open的执行语句即可进入到Binder驱动程序的binder_open()函数：

```c
    bs->fd = open("/dev/binder", O_RDWR);
```

函数binder_open()的实现代码如下所示:
```c
    static int binder_open(struct inode *nodp, struct file *filp)
    {
        struct binder_proc *proc;
        if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
            printk(KERN_INFO "binder_open: %d:%d\n", current->group_leader->pid, current->pid);
        proc = kzalloc(sizeof(*proc), GFP_KERNEL);
        if (proc == NULL)
            return -ENOMEM;
        get_task_struct(current);
        proc->tsk = current;
        INIT_LIST_HEAD(&proc->todo);
        init_waitqueue_head(&proc->wait);
        proc->default_priority = task_nice(current);
        mutex_lock(&binder_lock);
        binder_stats.obj_created[BINDER_STAT_PROC]++;
        hlist_add_head(&proc->proc_node, &binder_procs);
        proc->pid = current->group_leader->pid;
        INIT_LIST_HEAD(&proc->delivered_death);
        filp->private_data = proc;
        mutex_unlock(&binder_lock);
        if (binder_proc_dir_entry_proc) {
            char strbuf[11];
            snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
            remove_proc_entry(strbuf, binder_proc_dir_entry_proc);
            create_proc_read_entry(strbuf, S_IRUGO, binder_proc_dir_entry_proc, binder_read_proc_proc, proc);
    }
    return 0;
}
```

<font coloro="#DC143C"> 
    <b>
    函数binder_open()的主要功能是创建一个名为binder_proc的数据结构，使用此数据结构可以保存打开设备文件“/dev/binder”的进程的上下文信息，并且将这个进程上下文信息保存在打开文件结构file的私有数据成员变量private_data中。
    </b>
</font>
    
    而结构体struct binder_proc也被定义在文件“kernel/common/drivers/staging/android/binder.c”中，具体代码如下所示：
    
```c
    struct binder_proc {
    struct hlist_node proc_node;
    struct rb_root threads; // 用来保存binder_proc进程内用于处理用户请求的线程，它的最大数量由max_threads来决定
    struct rb_root nodes; // 用来保存binder_proc进程内的Binder实体
    struct rb_root refs_by_desc; // 以句柄作来key值来组织保存其它进程的Binder实体
    struct rb_root refs_by_node; // 以引用的实体节点的地址值作来key值组织保存Binder实体
    int pid;
    struct vm_area_struct *vma;
    struct task_struct *tsk;
    struct files_struct *files;
    struct hlist_node deferred_work_node;
    int deferred_work;
    void *buffer; // 是一个void*指针，它表示要映射的物理内存在内核空间中的起始位置。
    ptrdiff_t user_buffer_offset; // 是一个ptrdiff_t类型的变量，它表示的是内核使用的虚拟地址与进程使用的虚拟地址之间的差值
    struct list_head buffers;
    struct rb_root free_buffers;
    struct rb_root allocated_buffers;
    size_t free_async_space;
    struct page **pages; // 是一个struct page*类型的数组，struct page是用来描述物理页面的数据结构。
    size_t buffer_size; // 是一个size_t类型的变量，表示要映射的内存的大小。
    uint32_t buffer_free;
    struct list_head todo;
    wait_queue_head_t wait;
    struct binder_stats stats;
    struct list_head delivered_death;
    int max_threads;
    int requested_threads;
    int requested_threads_started;
    int ready_threads;
    long default_priority;
};

```
上述结构体中的成员比较多，其中最为重要的是如下4个成员变量。

- Threads
- Nodes 
- refs_by_desc
- refs_by_node

上述4个成员变量都是表示红黑树的节点，即binder_proc分别挂在4个红黑树下，具体说明如下所示。

- threads树：用来保存binder_proc进程内用于处理用户请求的线程，它的最大数量由max_threads来决定。
- node树：用来保存binder_proc进程内的Binder实体。
- refs_by_desc树和refs_by_node树：用来保存binder_proc进程内的Binder引用，即引用的其他进程的Binder实体，它分别用两种方式来组织红黑树，一种是- - 以句柄作来key值来组织，一种是以引用的实体节点的地址值作来key值来组织，它们都是表示同一样东西，只不过是为了内部查找方便而用两个红黑树来表示。

这样就完成了打开设备文件/dev/binder的工作，接下来需要对打开的设备文件进行内存映射操作mmap：

```c
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
```
对应Binder驱动程序的是函数binder_mmap()，实现代码如下所示：

```c
    static int binder_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret;
    struct vm_struct *area;
    struct binder_proc *proc = filp->private_data;
    const char *failure_string;
    struct binder_buffer *buffer;
    if ((vma->vm_end - vma->vm_start) > SZ_4M)
        vma->vm_end = vma->vm_start + SZ_4M;
    if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
        printk(KERN_INFO
            "binder_mmap: %d %lx-%lx (%ld K) vma %lx pagep %lx\n",
            proc->pid, vma->vm_start, vma->vm_end,
            (vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
            (unsigned long)pgprot_val(vma->vm_page_prot));
    if (vma->vm_flags & FORBIDDEN_MMAP_FLAGS) {
        ret = -EPERM;
        failure_string = "bad vm_flags";
        goto err_bad_arg;
    }
    vma->vm_flags = (vma->vm_flags | VM_DONTCOPY) & ~VM_MAYWRITE;
    if (proc->buffer) {
        ret = -EBUSY;
        failure_string = "already mapped";
        goto err_already_mapped;
    }
    area = get_vm_area(vma->vm_end - vma->vm_start, VM_IOREMAP);
    if (area == NULL) {
        ret = -ENOMEM;
        failure_string = "get_vm_area";
        goto err_get_vm_area_failed;
    }
    proc->buffer = area->addr;
    proc->user_buffer_offset = vma->vm_start - (uintptr_t)proc->buffer;
#ifdef CONFIG_CPU_CACHE_VIPT
    if (cache_is_vipt_aliasing()) {
        while (CACHE_COLOUR((vma->vm_start ^ (uint32_t)proc->buffer))) {
            printk(KERN_INFO "binder_mmap: %d %lx-%lx maps %p bad alignment\n", proc->pid,   
            vma->vm_start, vma->vm_end, proc->buffer);
            vma->vm_start += PAGE_SIZE;
        }
    }
#endif
    proc->pages = kzalloc(sizeof(proc->pages[0]) * ((vma->vm_end - vma->vm_start) /   
    PAGE_SIZE), GFP_KERNEL);
    if (proc->pages == NULL) {
        ret = -ENOMEM;
        failure_string = "alloc page array";
        goto err_alloc_pages_failed;
    }
    proc->buffer_size = vma->vm_end - vma->vm_start;
    vma->vm_ops = &binder_vm_ops;
    vma->vm_private_data = proc;
    if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PAGE_SIZE, vma)) {
        ret = -ENOMEM;
        failure_string = "alloc small buf";
        goto err_alloc_small_buf_failed;
    }
    buffer = proc->buffer;
    INIT_LIST_HEAD(&proc->buffers);
    list_add(&buffer->entry, &proc->buffers);
    buffer->free = 1;
    binder_insert_free_buffer(proc, buffer);
    proc->free_async_space = proc->buffer_size / 2;
    barrier();
    proc->files = get_files_struct(current);
    proc->vma = vma;
    /*printk(KERN_INFO "binder_mmap: %d %lx-%lx maps %p\n", proc->pid, vma->vm_start,   
    vma->vm_end, proc->buffer);*/
    return 0;
    err_alloc_small_buf_failed:
    kfree(proc->pages);
    proc->pages = NULL;
    err_alloc_pages_failed:
    vfree(proc->buffer);
    proc->buffer = NULL;
err_get_vm_area_failed:
err_already_mapped:
err_bad_arg:
    printk(KERN_ERR "binder_mmap: %d %lx-%lx %s failed %d\n", proc->pid, vma->vm_start, vma->vm_end, failure_string, ret);
    return ret;
}

```

在上述函数binder_mmap()中，首先通过filp->private_data得到在打开设备文件“/dev/binder”时创建的结构binder_proc，在vma参数中保存内存映射信息。此处vma的数据类型是结构vm_area_struct，它表示的是一块连续的虚拟地址空间区域。另外，结构体vm_struct表示一块连续的虚拟地址空间区域。

接下来分析结构体binder_proc中的如下成员变量。

- buffer：是一个void*指针，它表示要映射的物理内存在内核空间中的起始位置。
- buffer_size：是一个size_t类型的变量，表示要映射的内存的大小。
- pages：是一个struct page*类型的数组，struct page是用来描述物理页面的数据结构。
- user_buffer_offset：是一个ptrdiff_t类型的变量，它表示的是内核使用的虚拟地址与进程使用的虚拟地址之间的差值，即如果某个物理页面在内核空间中对应- 的虚拟地址为addr，则这个物理页面在进程空间对应的虚拟地址就为如下格式。

```c
   addr + user_buffer_offset 
```

接下来还需要看一下Binder驱动程序管理内存映射地址空间的方法，即如何管理buffer～(buffer + buffer_size)这段地址空间，这个地址空间被划分为一段一段来管理，每一段是用结构体binder_buffer来描述的，具体代码如下所示：

```c
    struct binder_buffer {
    struct list_head entry; /* free and allocated entries by addesss */
    struct rb_node rb_node; /* free entry by size or allocated entry */
                /* by address */
    unsigned free : 1;
    unsigned allow_user_free : 1;
    unsigned async_transaction : 1;
    unsigned debug_id : 29;
    struct binder_transaction *transaction;
    struct binder_node *target_node;
    size_t data_size;
    size_t offsets_size;
    uint8_t data[0];
};
```
每一个binder_buffer通过其成员entry按从低地址到高地址连入到struct binder_proc中的buffers表示的链表中去，并且每一个binder_buffer又分为正在使用的和空闲的，通过free成员变量来区分。空闲的binder_buffer借助变量rb_node来到struct binder_proc中的free_buffers表示的红黑树中去；而那些正在使用的binder_buffer，通过成员变量rb_node连入到binder_proc中的allocated_buffers表示的红黑树中去。这样做的目的是，方便查询和维护这块地址空间。

继续分析函数binder_update_page_range()，查看Binder驱动程序把一个物理页面同时映射到内核空间和进程空间的方法。具体实现代码如下所示：

```c
    static int binder_update_page_range(struct binder_proc *proc, int allocate,
    void *start, void *end, struct vm_area_struct *vma)
{
    void *page_addr;
    unsigned long user_page_addr;
    struct vm_struct tmp_area;
    struct page **page;
    struct mm_struct *mm;
    if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
        printk(KERN_INFO "binder: %d: %s pages %p-%p\n",
               proc->pid, allocate ? "allocate" : "free", start, end);
    if (end <= start)
        return 0;
    if (vma)
        mm = NULL;
    else
        mm = get_task_mm(proc->tsk);
    if (mm) {
        down_write(&mm->mmap_sem);
        vma = proc->vma;
    }
    if (allocate == 0)
        goto free_range;
    if (vma == NULL) {
        printk(KERN_ERR "binder: %d: binder_alloc_buf failed to "
               "map pages in userspace, no vma\n", proc->pid);
        goto err_no_vma;
    }
    for (page_addr = start; page_addr < end; page_addr += PAGE_SIZE) {
        int ret;
        struct page **page_array_ptr;
        page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
        BUG_ON(*page);
        *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (*page == NULL) {
            printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
                   "for page at %p\n", proc->pid, page_addr);
            goto err_alloc_page_failed;
        }
        tmp_area.addr = page_addr;
        tmp_area.size = PAGE_SIZE + PAGE_SIZE /* guard page? */;
        page_array_ptr = page;
        ret = map_vm_area(&tmp_area, PAGE_KERNEL, &page_array_ptr);
        if (ret) {
            printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
                   "to map page at %p in kernel\n",
                   proc->pid, page_addr);
            goto err_map_kernel_failed;
        }
        user_page_addr =
            (uintptr_t)page_addr + proc->user_buffer_offset;
        ret = vm_insert_page(vma, user_page_addr, page[0]);
        if (ret) {
            printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
                   "to map page at %lx in userspace\n",
                   proc->pid, user_page_addr);
            goto err_vm_insert_page_failed;
        }
        /* vm_insert_page does not seem to increment the refcount */
    }
    if (mm) {
        up_write(&mm->mmap_sem);
        mmput(mm);
    }
    return 0;
free_range:
    for (page_addr = end - PAGE_SIZE; page_addr >= start;
         page_addr -= PAGE_SIZE) {
        page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
        if (vma)
            zap_page_range(vma, (uintptr_t)page_addr +
                proc->user_buffer_offset, PAGE_SIZE, NULL);
err_vm_insert_page_failed:
        unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
err_map_kernel_failed:
        __free_page(*page);
        *page = NULL;
err_alloc_page_failed:
        ;
    }
err_no_vma:
    if (mm) {
        up_write(&mm->mmap_sem);
        mmput(mm);
    }
    return -ENOMEM;
}

```
上述代码的具体实现流程如下所示。

-（1）调用alloc_page()分配一个物理页面，此函数返回一个结构体page物理页面描述符，根据这个描述的内容初始化好结构体vm_struct tmp_area。

-（2）通过map_vm_area将这个物理页面插入到tmp_area描述的内核空间中。

-（3）通过page_addr + proc->user_buffer_offset获得进程虚拟空间地址。

-（4）通过函数vm_insert_page()将这个物理页面插入到进程地址空间去，参数vma表示要插入的进程的地址空间。

再次回到文件“frameworks/base/cmds/servicemanager/service_manager.c”中的main()函数，接下来需要调用binder_become_context_manager来通知Binder驱动程序自己是Binder机制的上下文管理者，即保护进程。函数binder_become_context_manager()在文件“frameworks/base/cmds/ servicemanager/binder.c”中定义，具体代码如下所示：

```c
    int binder_become_context_manager(struct binder_state *bs){
    return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);
}
```
在此通过调用ioctl文件操作函数通知Binder驱动程序自己是保护进程，命令号是BINDER_SET_CONTEXT_MGR，并没有任何参数。BINDER_SET_CONTEXT_MGR定义为：

```c
    #define    BINDER_SET_CONTEXT_MGR _IOW('b', 7, int)

```
这样就进入到Binder驱动程序的函数binder_ioctl()，在此只关注如下BINDER_SET_CONTEXT_MGR命令即可，具体代码如下所示：

```c
    static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret;
    struct binder_proc *proc = filp->private_data;
    struct binder_thread *thread;
    unsigned int size = _IOC_SIZE(cmd);
    void __user *ubuf = (void __user *)arg;
    /*printk(KERN_INFO "binder_ioctl: %d:%d %x %lx\n", proc->pid, current->pid, cmd, arg);*/
    ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    if (ret)
        return ret;
    mutex_lock(&binder_lock);
    thread = binder_get_thread(proc);
    if (thread == NULL) {
        ret = -ENOMEM;
        goto err;
    }
    switch (cmd) {
        ......
    case BINDER_SET_CONTEXT_MGR:
        if (binder_context_mgr_node != NULL) {
            printk(KERN_ERR "binder: BINDER_SET_CONTEXT_MGR already set\n");
            ret = -EBUSY;
            goto err;
        }
        if (binder_context_mgr_uid != -1) {
            if (binder_context_mgr_uid != current->cred->euid) {
                printk(KERN_ERR "binder: BINDER_SET_"
                    "CONTEXT_MGR bad uid %d != %d\n",
                    current->cred->euid,
                    binder_context_mgr_uid);
                ret = -EPERM;
                goto err;
            }
        } else
            binder_context_mgr_uid = current->cred->euid;
        binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
        if (binder_context_mgr_node == NULL) {
            ret = -ENOMEM;
            goto err;
        }
        binder_context_mgr_node->local_weak_refs++;
        binder_context_mgr_node->local_strong_refs++;
        binder_context_mgr_node->has_strong_ref = 1;
        binder_context_mgr_node->has_weak_ref = 1;
        break;
        ......
    default:
        ret = -EINVAL;
        goto err;
    }
    ret = 0;
err:
    if (thread)
        thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
    mutex_unlock(&binder_lock);
    wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    if (ret && ret != -ERESTARTSYS)
        printk(KERN_INFO "binder: %d:%d ioctl %x %lx returned %d\n", proc->pid, current->pid,   
        cmd, arg, ret);
    return ret;
}
```
在分析函数binder_ioctl()之前，需要先弄明白如下两个数据结构的含义。

- （1）结构体binder_thread：表示一个线程，这里就是执行binder_become_context_manager()函数的线程。具体代码如下所示：
```c
    struct binder_thread {
    struct binder_proc *proc;
    struct rb_node rb_node;
    int pid;
    int looper;
    struct binder_transaction *transaction_stack;
    struct list_head todo;
    uint32_t return_error; /* Write failed, return error code in read buf */
    uint32_t return_error2; /* Write failed, return error code in read */
        /* buffer. Used when sending a reply to a dead process that */
        /* we are also waiting on */
    wait_queue_head_t wait;
    struct binder_stats stats;
};
```
在上述结构体中，proc表示是这个线程所属的进程。结构体binder_proc中成员变量thread的类型是rb_root，它表示一棵红黑树，把属于这个进程的所有线程都组织起来，结构体binder_thread的成员变量rb_node就是用来链入这棵红黑树的节点了。looper成员变量表示线程的状态，可以取如下所示的值：

```c
    enum {
    BINDER_LOOPER_STATE_REGISTERED  = 0x01,
    BINDER_LOOPER_STATE_ENTERED     = 0x02,
    BINDER_LOOPER_STATE_EXITED      = 0x04,
    BINDER_LOOPER_STATE_INVALID     = 0x08,
    BINDER_LOOPER_STATE_WAITING     = 0x10,
    BINDER_LOOPER_STATE_NEED_RETURN = 0x20
};

```
 另外，transaction_stack表示线程正在处理的事务，todo表示发往该线程的数据列表，return_error和return_error2表示操作结果返回码，wait用来阻塞线程等待某个事件的发生，stats用来保存一些统计信息。这些成员变量遇到的时候再分析它们的作用。   
 
（2）数据结构binder_node：表示一个binder实体，具体代码如下所示：

```c
    struct binder_node {
    int debug_id;
    struct binder_work work;
    union {
        struct rb_node rb_node;
        struct hlist_node dead_node;
    };
    struct binder_proc *proc;
    struct hlist_head refs;
    int internal_strong_refs;
    int local_weak_refs;
    int local_strong_refs;
    void __user *ptr;
    void __user *cookie;
    unsigned has_strong_ref : 1;
    unsigned pending_strong_ref : 1;
    unsigned has_weak_ref : 1;
    unsigned pending_weak_ref : 1;
    unsigned has_async_transaction : 1;
    unsigned accept_fds : 1;
    int min_priority : 8;
    struct list_head async_todo;
};

```

由此可见，rb_node和dead_node组成了一个联合体，具体来说分为如下两种情形。

- 如果这个Binder实体还在正常使用，则使用rb_node来连入“proc->nodes”所表示的红黑树的节点，这棵红黑树用来组织属于这个进程的所有Binder实体。
- 如果这个Binder实体所属的进程已经销毁，而这个Binder实体又被其他进程所引用，则这个Binder实体通过dead_node进入到一个哈希表中去存放。proc成员变量就是表示这个Binder实例所属于进程了。

在上述数据结构binder_node中，主要成员的具体说明如下所示。

- refs：把所有引用了该Binder实体的Binder引用连接起来构成一个链表。
- internal_strong_refs、local_weak_refs和local_strong_refs：表示这个Binder实体的引用计数。
- ptr和cookie：分别表示这个Binder实体在用户空间的地址以及附加数据。

接下来回到函数binder_ioctl()中，首先是通过“filp->private_data”获得proc变量，此处的函数binder_mmap()是一样的，然后通过函数binder_get_thread()获得线程信息，此函数的代码如下所示：

```c
    static struct binder_thread *binder_get_thread(struct binder_proc *proc)
{
    struct binder_thread *thread = NULL;
    struct rb_node *parent = NULL;
    struct rb_node **p = &proc->threads.rb_node;
    while (*p) {
        parent = *p;
        thread = rb_entry(parent, struct binder_thread, rb_node);
        if (current->pid < thread->pid)
            p = &(*p)->rb_left;
        else if (current->pid > thread->pid)
            p = &(*p)->rb_right;
        else
            break;
    }
    if (*p == NULL) {
        thread = kzalloc(sizeof(*thread), GFP_KERNEL);
        if (thread == NULL)
            return NULL;
        binder_stats.obj_created[BINDER_STAT_THREAD]++;
        thread->proc = proc;
        thread->pid = current->pid;
        init_waitqueue_head(&thread->wait);
        INIT_LIST_HEAD(&thread->todo);
        rb_link_node(&thread->rb_node, parent, p);
        rb_insert_color(&thread->rb_node, &proc->threads);
        thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
        thread->return_error = BR_OK;
        thread->return_error2 = BR_OK;
    }
    return thread;
}
```

在上述代码中，把当前线程current的pid作为键值，在进程proc->threads表示的红黑树中进行查找，看是否已经为当前线程创建过了binder_thread信息。在这个场景下，由于当前线程是第一次进到这里，所以肯定找不到，即*p == NULL成立，于是，就为当前线程创建一个线程上下文信息结构体binder_thread，并初始化相应成员变量，并插入到proc->threads所表示的红黑树中去，下次要使用时就可以从proc中找到了。注意，这里的thread->looper = BINDER_LOOPER_STATE_NEED_RETURN。

再回到函数binder_ioctl()中，接下来会有binder_context_mgr_node和binder_context_mgr_uid两个全局变量，定义如下所示：

```c
    static struct binder_node *binder_context_mgr_node;
    static uid_t binder_context_mgr_uid = -1;
```
其中binder_context_mgr_node用来表示Service Manager实体，binder_context_mgr_uid表示Service Manager保护进程的uid。在这个场景下，由于当前线程是第一次进到这里，所以binder_context_mgr_node为NULL，binder_context_mgr_uid为−1，于是初始化binder_context_mgr_uid为current->cred->euid，这样当前线程就成为Binder机制的保护进程了，并且通过binder_new_node为Service Manager创建Binder实体：

```c
    static struct binder_node *
binder_new_node(struct binder_proc *proc, void __user *ptr, void __user *cookie)
{
    struct rb_node **p = &proc->nodes.rb_node;
    struct rb_node *parent = NULL;
    struct binder_node *node;
    while (*p) {
        parent = *p;
        node = rb_entry(parent, struct binder_node, rb_node);
        if (ptr < node->ptr)
            p = &(*p)->rb_left;
        else if (ptr > node->ptr)
            p = &(*p)->rb_right;
        else
            return NULL;
    }
    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (node == NULL)
        return NULL;
    binder_stats.obj_created[BINDER_STAT_NODE]++;
    rb_link_node(&node->rb_node, parent, p);
    rb_insert_color(&node->rb_node, &proc->nodes);
    node->debug_id = ++binder_last_id;
    node->proc = proc;
    node->ptr = ptr;
    node->cookie = cookie;
    node->work.type = BINDER_WORK_NODE;
    INIT_LIST_HEAD(&node->work.entry);
    INIT_LIST_HEAD(&node->async_todo);
    if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
        printk(KERN_INFO "binder: %d:%d node %d u%p c%p created\n",
               proc->pid, current->pid, node->debug_id,
               node->ptr, node->cookie);
    return node;
}
```

在这里传进来的ptr和cookie都为NULL。上述函数会首先检查proc->nodes红黑树中是否已经存在以ptr为键值的node，如果已经存在则返回NULL。在这个场景下，由于当前线程是第一次进入到这里，所以肯定不存在，于是就新建了一个ptr为NULL的binder_node，并且初始化其他成员变量，并插入到proc->nodes红黑树中去。

当binder_new_node返回到函数binder_ioctl()后，会把新建的binder_node指针保存在binder_context_mgr_node中，然后又初始化binder_context_mgr_node的引用计数值。这样执行BINDER_SET_CONTEXT_MGR命令完毕，在函数binder_ioctl()返回之前执行下面的语句：

```c
    if (thread)
        thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
```

再次回到文件“frameworks/base/cmds/servicemanager/service_manager.c”中的main()函数，接下来需要调用函数binder_loop()进入循环，等待Client发送请求。函数binder_loop()定义在文件“frameworks/base/cmds/servicemanager/binder.c”中：

```c
void binder_loop(struct binder_state *bs, binder_handler func)
{
    int res;
    struct binder_write_read bwr;
    unsigned readbuf[32];
    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;
    readbuf[0] = BC_ENTER_LOOPER;
    binder_write(bs, readbuf, sizeof(unsigned));
    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (unsigned) readbuf;
        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
        if (res < 0) {
            LOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
            break;
        }
        res = binder_parse(bs, 0, readbuf, bwr.read_consumed, func);
        if (res == 0) {
            LOGE("binder_loop: unexpected reply?!\n");
            break;
        }
        if (res < 0) {
            LOGE("binder_loop: io error %d %s\n", res, strerror(errno));
            break;
        }
    }
}
```
在上述代码中，首先通过函数binder_write()执行BC_ENTER_LOOPER命令以告诉Binder驱动程序，Service Manager马上要进入循环。在此还需要理解设备文件“/dev/binder”操作函数ioctl的操作码BINDER_WRITE_READ，首先看其定义：

```c
    #define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
```

此IO操作码有一个形式为struct binder_write_read的参数，具体代码如下所示：

```c
    struct binder_write_read {
    signed long    write_size;    /* bytes to write */
    signed long    write_consumed;    /* bytes consumed by driver */
    unsigned long    write_buffer;
    signed long    read_size;    /* bytes to read */
    signed long    read_consumed;    /* bytes consumed by driver */
    unsigned long    read_buffer;
};
```
用户空间程序和Binder驱动程序交互时，大多数是通过BINDER_WRITE_READ命令实现的，write_bufffer和read_buffer所指向的数据结构还指定了具体要执行的操作，write_bufffer和read_buffer所指向的结构体是binder_transaction_data，定义此结构体的具体代码如下所示：

```c
    struct binder_transaction_data {
    /* The first two are only used for bcTRANSACTION and brTRANSACTION,
     * identifying the target and contents of the transaction.
     */
    union {
        size_t    handle;    /* target descriptor of command transaction */
        void    *ptr;    /* target descriptor of return transaction */
    } target;
    void        *cookie;    /* target object cookie */
    unsigned int    code;        /* transaction command */
    /* General information about the transaction. */
    unsigned int    flags;
    pid_t        sender_pid;
    uid_t        sender_euid;
    size_t        data_size;    /* number of bytes of data */
    size_t        offsets_size;    /* number of bytes of offsets */
    /* If this transaction is inline, the data immediately
     * follows here; otherwise, it ends with a pointer to
     * the data buffer.
     */
    union {
        struct {
            /* transaction data */
            const void    *buffer;
            /* offsets from buffer to flat_binder_object structs */
            const void    *offsets;
        } ptr;
        uint8_t    buf[8];
    } data;
}
```
到此为止，已经从源代码一步一步地分析完Service Manager是如何成为Android进程间通信（IPC）机制Binder保护进程的。在接下来的内容中，简要总结Service Manager成为Android进程间通信（IPC）机制Binder保护进程的过程。

（1）打开/dev/binder文件：
```c
    open("/dev/binder", O_RDWR);
```
（2）建立128K内存映射：
```c
    mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
```
（3）通知Binder驱动程序它是保护进程：
```c
    binder_become_context_manager(bs);
```
（4）进入循环等待请求的到来：
```c
    binder_loop(bs, svcmgr_handler);
```

在这个过程中，在Binder驱动程序中建立了一个struct binder_proc结构、一个struct　binder_thread结构和一个struct binder_node结构，这样，Service Manager就在Android系统的进程间通信机制Binder担负起保护进程的职责了


