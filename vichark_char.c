#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#define DEVICE_NAME "vicharak"
#define CLASS_NAME  "vicharak_class"

// ---------- IOCTL defs (match user-space) ----------
#define IOCTL_MAGIC 'a'
#define SET_SIZE_OF_QUEUE _IOW(IOCTL_MAGIC, 'a', int *)
/* Note: the structure contains a user pointer. We define a kernel-visible
 * version that uses __user for clarity and safety. */
struct data_ioctl {
    int length;
    char __user *data;
};
#define PUSH_DATA _IOW(IOCTL_MAGIC, 'b', struct data_ioctl *)
#define POP_DATA  _IOR(IOCTL_MAGIC, 'c', struct data_ioctl *)

// ---------- Circular queue state ----------
struct vicharak_dev {
    struct cdev cdev;
    struct class *class;
    struct device *device;
    dev_t devno;

    char *buf;          // circular buffer storage
    size_t capacity;    // allocated size in bytes
    size_t head;        // read index
    size_t tail;        // write index
    size_t size;        // current bytes in buffer

    struct mutex lock;          // protects queue + parameters
    wait_queue_head_t can_read; // waiters for data arrival
    wait_queue_head_t can_write;// (optional) if you extend to blocking writer
};

static struct vicharak_dev *gdev;

// ---------- helpers ----------
static void q_reset(struct vicharak_dev *d)
{
    d->head = d->tail = d->size = 0;
}

static size_t q_free(const struct vicharak_dev *d)
{
    return d->capacity - d->size;
}

static size_t q_read(struct vicharak_dev *d, char *dst, size_t len)
{
    size_t copied = 0;
    while (copied < len && d->size > 0) {
        size_t chunk = min(len - copied, d->capacity - d->head);
        chunk = min(chunk, d->size);
        memcpy(dst + copied, d->buf + d->head, chunk);
        d->head = (d->head + chunk) % d->capacity;
        d->size -= chunk;
        copied += chunk;
    }
    return copied;
}
static size_t q_write(struct vicharak_dev *d, const char *src, size_t len)
{
    size_t written = 0;
    while (written < len && d->size < d->capacity) {
        size_t chunk = min(len - written, d->capacity - d->tail);
        chunk = min(chunk, d->capacity - d->size);
        memcpy(d->buf + d->tail, src + written, chunk);
        d->tail = (d->tail + chunk) % d->capacity;
        d->size += chunk;
        written += chunk;
    }
    return written;
}

// ---------- file ops ----------
static long vicharak_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct vicharak_dev *d = gdev;
    int ret = 0;

    switch (cmd) {
    case SET_SIZE_OF_QUEUE: {
        int newcap = 0;
        if (copy_from_user(&newcap, (void __user *)arg, sizeof(newcap)))
            return -EFAULT;
        if (newcap <= 0)
            return -EINVAL;

        mutex_lock(&d->lock);
        // Allocate new buffer
        char *newbuf = kmalloc(newcap, GFP_KERNEL);
        if (!newbuf) {
            mutex_unlock(&d->lock);
            return -ENOMEM;
        }
        kfree(d->buf);
        d->buf = newbuf;
        d->capacity = newcap;
        q_reset(d);
        mutex_unlock(&d->lock);
        // Optionally wake up any waiters (now empty)
        wake_up_interruptible(&d->can_read);
        return 0;
    }
}}
static int vicharak_open(struct inode *inode, struct file *file)
{
    // Nothing fancy; device is shared
    return 0;
}

static int vicharak_release(struct inode *inode, struct file *file)
{
    return 0;
}

static const struct file_operations vicharak_fops = {
    .owner          = THIS_MODULE,
    .open           = vicharak_open,
    .release        = vicharak_release,
    .unlocked_ioctl = vicharak_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = vicharak_ioctl, // simple structs; OK for demo
#endif
};

// ---------- module init/exit ----------
static int __init vicharak_init(void)
{
    int err;

    gdev = kzalloc(sizeof(*gdev), GFP_KERNEL);
    if (!gdev) return -ENOMEM;

    err = alloc_chrdev_region(&gdev->devno, 0, 1, DEVICE_NAME);
    if (err) goto fail_alloc;

    cdev_init(&gdev->cdev, &vicharak_fops);
    gdev->cdev.owner = THIS_MODULE;
    err = cdev_add(&gdev->cdev, gdev->devno, 1);
    if (err) goto fail_cdev;

    gdev->class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(gdev->class)) { err = PTR_ERR(gdev->class); goto fail_class; }

    gdev->device = device_create(gdev->class, NULL, gdev->devno, NULL, DEVICE_NAME);
    if (IS_ERR(gdev->device)) { err = PTR_ERR(gdev->device); goto fail_device; }

    mutex_init(&gdev->lock);
    init_waitqueue_head(&gdev->can_read);
    init_waitqueue_head(&gdev->can_write);

    gdev->buf = NULL;
    gdev->capacity = 0;
    q_reset(gdev);

    pr_info("vicharak: loaded (major=%d minor=%d) /dev/%s\n",
            MAJOR(gdev->devno), MINOR(gdev->devno), DEVICE_NAME);
    return 0;

fail_device:
    class_destroy(gdev->class);
fail_class:
    cdev_del(&gdev->cdev);
fail_cdev:
    unregister_chrdev_region(gdev->devno, 1);
fail_alloc:
    kfree(gdev);
    return err;
}

static void __exit vicharak_exit(void)
{
    if (gdev) {
        device_destroy(gdev->class, gdev->devno);
        class_destroy(gdev->class);
        cdev_del(&gdev->cdev);
        unregister_chrdev_region(gdev->devno, 1);
        kfree(gdev->buf);
        kfree(gdev);
    }
    pr_info("vicharak: unloaded\n");
}

module_init(vicharak_init);
module_exit(vicharak_exit);

MODULE_AUTHOR("vicharak");
MODULE_DESCRIPTION("Blocking circular-queue char device using IOCTL");
MODULE_LICENSE("GPL");
