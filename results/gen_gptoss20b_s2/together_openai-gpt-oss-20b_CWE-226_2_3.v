```verilog
// CWE: CWE-226
module simple_cipher(
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire [127:0] data_in,
    input  wire [127:0] key_in,
    output reg