file(READ "${INPUT}" hex_content HEX)
string(LENGTH "${hex_content}" hex_length)
math(EXPR byte_count "${hex_length} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," byte_list "${hex_content}")

file(WRITE "${OUTPUT}"
     "/* Generated from ${INPUT}; do not edit. */\n"
     "const unsigned char ${SYMBOL}[] = {${byte_list}};\n"
     "const unsigned int ${SYMBOL}_len = ${byte_count};\n")
