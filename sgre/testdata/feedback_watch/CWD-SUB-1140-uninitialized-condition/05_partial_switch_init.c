int check_mode(int selector)
{
    int mode;

    switch (selector) {
    case 0:
        mode = 10;
        break;
    case 1:
        mode = 20;
        break;
    default:
        break;
    }

    if (mode == 10 || mode == 20) {
        return 1;
    }

    return 0;
}
