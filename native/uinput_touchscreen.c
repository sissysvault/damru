// Virtual multi-touch touchscreen with configurable device name.
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;
static void on_signal(int sig) { (void)sig; keep_running = 0; }

static int set_bit(int fd, unsigned long req, int val) {
    if (ioctl(fd, req, val) < 0) {
        fprintf(stderr, "ioctl failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static void configure_abs(struct uinput_user_dev *dev, int code, int min, int max) {
    dev->absmin[code] = min; dev->absmax[code] = max;
    dev->absfuzz[code] = 0; dev->absflat[code] = 0;
}

int main(int argc, char **argv) {
    const char *name = "goodix_ts";
    int width = 1080, height = 2400, slots = 10;
    int vendor = 0x27c6; int product = 0x0d42;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--name") && i + 1 < argc) name = argv[++i];
        else if (!strcmp(argv[i], "--width") && i + 1 < argc) width = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--height") && i + 1 < argc) height = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--slots") && i + 1 < argc) slots = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--vendor") && i + 1 < argc) vendor = strtol(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--product") && i + 1 < argc) product = strtol(argv[++i], NULL, 0);
    }
    if (width <= 0) width = 1080;
    if (height <= 0) height = 2400;
    if (slots < 2) slots = 5;
    if (slots > 10) slots = 10;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) { fprintf(stderr, "open uinput: %s\n", strerror(errno)); return 1; }

    if (set_bit(fd, UI_SET_EVBIT, EV_KEY) ||
        set_bit(fd, UI_SET_KEYBIT, BTN_TOUCH) ||
        set_bit(fd, UI_SET_KEYBIT, BTN_TOOL_FINGER) ||
        set_bit(fd, UI_SET_EVBIT, EV_ABS) ||
        set_bit(fd, UI_SET_ABSBIT, ABS_X) ||
        set_bit(fd, UI_SET_ABSBIT, ABS_Y) ||
        set_bit(fd, UI_SET_ABSBIT, ABS_MT_SLOT) ||
        set_bit(fd, UI_SET_ABSBIT, ABS_MT_TRACKING_ID) ||
        set_bit(fd, UI_SET_ABSBIT, ABS_MT_POSITION_X) ||
        set_bit(fd, UI_SET_ABSBIT, ABS_MT_POSITION_Y) ||
        set_bit(fd, UI_SET_ABSBIT, ABS_MT_TOUCH_MAJOR) ||
        set_bit(fd, UI_SET_ABSBIT, ABS_MT_PRESSURE)) { close(fd); return 1; }

#ifdef UI_SET_PROPBIT
    ioctl(fd, UI_SET_PROPBIT, INPUT_PROP_DIRECT);
#endif

    struct uinput_user_dev dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, name, sizeof(dev.name) - 1);
    dev.id.bustype = BUS_I2C;
    dev.id.vendor = vendor;
    dev.id.product = product;
    dev.id.version = 1;

    configure_abs(&dev, ABS_X, 0, width - 1);
    configure_abs(&dev, ABS_Y, 0, height - 1);
    configure_abs(&dev, ABS_MT_SLOT, 0, slots - 1);
    configure_abs(&dev, ABS_MT_TRACKING_ID, 0, 65535);
    configure_abs(&dev, ABS_MT_POSITION_X, 0, width - 1);
    configure_abs(&dev, ABS_MT_POSITION_Y, 0, height - 1);
    configure_abs(&dev, ABS_MT_TOUCH_MAJOR, 0, 255);
    configure_abs(&dev, ABS_MT_PRESSURE, 0, 255);

    if (write(fd, &dev, sizeof(dev)) != sizeof(dev)) { fprintf(stderr, "write: %s\n", strerror(errno)); return 1; }
    if (ioctl(fd, UI_DEV_CREATE) < 0) { fprintf(stderr, "UI_DEV_CREATE: %s\n", strerror(errno)); return 1; }

    fprintf(stdout, "created uinput touchscreen name=%s %dx%d slots=%d\n", name, width, height, slots);
    fflush(stdout);
    while (keep_running) sleep(60);
    ioctl(fd, UI_DEV_DESTROY);
    close(fd);
    return 0;
}
