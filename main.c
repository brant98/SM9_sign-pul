#include <stdio.h>
#include<time.h>
#include"sm9_standard.h"
int main(void)
{
    clock_t start, finish;//计算运行时间用
    start = clock();

    for (int i = 0; i < 50; i++)
    {
	SM9_sign_test();

    }
    
    printf("\n\n");
    finish = clock();
    printf("Test of this algorithm finished\n");
  //  printf("Start at  %f s\n", (double)start / CLOCKS_PER_SEC);
  //  printf("End at %f s\n", (double)finish / CLOCKS_PER_SEC);
     printf("100 times tests  used %f seconds in total.\n", 2*(double)difftime(finish, start) / CLOCKS_PER_SEC);
    printf("The algorithm runs once used %f seconds on average.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC / 50);
	return 0;
}
