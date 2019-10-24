//gcc -o vuln source.c -fno-stack-protector  -no-pie
int main(){
    char local_20[32];
    puts("Simple ROP.\n");
    gets(local_20);
    return 0;
}
