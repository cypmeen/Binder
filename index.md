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
    struct rb_root threads;
    struct rb_root nodes;
    struct rb_root refs_by_desc;
    struct rb_root refs_by_node;
    int pid;
    struct vm_area_struct *vma;
    struct task_struct *tsk;
    struct files_struct *files;
    struct hlist_node deferred_work_node;
    int deferred_work;
    void *buffer;
    ptrdiff_t user_buffer_offset;
    struct list_head buffers;
    struct rb_root free_buffers;
    struct rb_root allocated_buffers;
    size_t free_async_space;
    struct page **pages;
    size_t buffer_size;
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





