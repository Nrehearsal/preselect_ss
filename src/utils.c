#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <regex.h>

#include "utils.h"

int
set_nonblock(int fd)
{
	int flags;
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags|O_NONBLOCK);
}

int
regex_ip(const char *ip) 
{
	int found = 0;
	int status = 0;

	regex_t reg;  
	int reg_flag = REG_EXTENDED;  
	regmatch_t pmatch[1];  

	const char *pattern="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]).){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$";

	regcomp(&reg, pattern, reg_flag);  

	status = regexec(&reg, ip, 1, pmatch, 0);  
	if(status == REG_NOMATCH) {
		found = 0;
	} else if(status==0) {  
		found = 1;
	} 

	regfree(&reg);  

	return found;
}

int
regex_domain(const char *domain) 
{
	int found = 0;
	int status = 0;

	regex_t reg;  
	int reg_flag = REG_EXTENDED;  
	regmatch_t pmatch[1];  

	const char *pattern="^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}$";

	regcomp(&reg, pattern, reg_flag);  

	status = regexec(&reg, domain, 1, pmatch, 0);  
	if(status == REG_NOMATCH) {
		found = 0;
	} else if(status==0) {  
		found = 1;
	} 

	regfree(&reg);  

	return found;
}
