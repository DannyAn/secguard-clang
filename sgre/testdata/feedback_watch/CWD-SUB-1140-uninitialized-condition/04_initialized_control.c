int check_state_safe(int input)
{
    int state = 0;

    if (input > 0) {
        state = 1;
    }

    if (state == 1) {
        return 0;
    }

    return -1;
}
