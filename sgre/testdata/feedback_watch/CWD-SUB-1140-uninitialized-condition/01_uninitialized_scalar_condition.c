int check_state(int input)
{
    int state;

    if (input > 0) {
        state = 1;
    }

    if (state == 1) {
        return 0;
    }

    return -1;
}
