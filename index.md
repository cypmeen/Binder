##　欢迎和我一起走进Android Binder机制

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

说实话，Android系统的Binder机制比较难以理解,而Bidner机制无论从系统开发还是应用开发的角度来看，都是Android系统中最重要的组成，所以很有必要深入了解Binder的工作方式，最好的方式还是阅读Binder相关的Fucking Code。




