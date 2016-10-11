//Function readline:
//Reads the next line from an open file descriptor, and returns it
//as a valid C string (terminating newline not included).
//Returns NULL in case of an error or end-of-file (check errno to
//distinguish between these cases).
//
//This is a STATIC LINE VERSION:
//Memory for the return string (char *) is allocated using malloc(),
//but is maintained between calls (in static memory) and reused,
//so the returned string will be overwritten by a subsequent call
//to readline.
//
//This is a BUFFERED FILE VERSION:
//Memory for the read buff is static, so the function can be used
//for only one open file descriptor at a time, and you must read
//to the end of each file before using it to read from another file.
//
//This version INCLUDES NEWLINES in returned string if a line if
//terminated by a newline (so may not be included with final line of file).
//
//Note that direct reads from fd should NOT be interspersed with calls
//to this function---use only this function to read from fd.
//
//Put this line in code after all header includes, to include function:
//  #include "readline.c"


#define FD_BUFFER_SIZE 4096
#define LINE_BUFFER_INCREMENT 100

char *readline(int fd)
{
  static char fd_buff[FD_BUFFER_SIZE];
  static int fd_buff_end = 0;
  static int fd_buff_pos = 0;
  static char *line_buff = NULL;
  static int line_buff_size = 0;

  char next_char;
  char *temp_line_buff;
  int line_buff_pos = 0;

  //Reset errno to avoid detecting previous errors:
  errno = 0;

  //See if line_buff needs to be initialized:
  if (line_buff == NULL) {
    if ((line_buff = malloc(LINE_BUFFER_INCREMENT)) == NULL)
      return NULL;
    line_buff_size = LINE_BUFFER_INCREMENT; }

  do {
    //Get next char from fd else break from loop if EOF:
    if (fd_buff_pos >= fd_buff_end) {
      if ((fd_buff_end=read(fd,fd_buff,FD_BUFFER_SIZE)) <= 0)
        break;
      fd_buff_pos = 0; }
    next_char = fd_buff[fd_buff_pos++];
    //If EOL not reached, store next char:
    if (next_char != '\n') {
      if ((line_buff_size - line_buff_pos) < 3) {
        if ((temp_line_buff = realloc(line_buff,line_buff_size + LINE_BUFFER_INCREMENT)) == NULL)
          break;
        line_buff_size = line_buff_size + LINE_BUFFER_INCREMENT; 
        line_buff = temp_line_buff; }
      line_buff[line_buff_pos++] = next_char; } }
  while (next_char != '\n');

  //Determine appropriate return value by checking if error or EOF were encountered:
  if (errno || (fd_buff_end == 0 && line_buff_pos == 0))
    return NULL;
  else {
    //Include newline if line was terminated by it:
    if (next_char == '\n') line_buff[line_buff_pos++] = '\n';
    //Be sure line buffer contains a legal string:
    line_buff[line_buff_pos] = '\0';
    return line_buff; }
}


// EOF
