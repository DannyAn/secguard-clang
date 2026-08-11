/*
 * TC17 - Uninit: Struct Partial Init / Field-Sensitive (REQ-TC-017)
 * Vulnerability: a struct is partially initialized — one field is set
 *                but another is read without being initialized.
 * Expected: finding produced (field-sensitive partial init)
 */

typedef struct Point {
    int x;
    int y;
} Point;

int tc17_uninit_struct_partial(void) {
    Point p;
    p.x = 10;
    return p.y;
}