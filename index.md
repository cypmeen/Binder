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









