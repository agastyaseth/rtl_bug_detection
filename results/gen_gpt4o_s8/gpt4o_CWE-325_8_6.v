// CWE: CWE-325
module insecure_hash(clk, rst, data_in, hash_out);
    input clk, rst;
    input [127:0] data_in;
    output reg [127:0] hash_out;
    wire [31:0] d0, d1, d2, d3;
    wire [31:0] h0, h1, h2, h3;

    assign {d0, d1, d2, d3} = data_in;

    // Missing a crucial cryptographic step here
    assign h0 = d0 ^ 32'h5A5A5A5A;
    assign h1 = d1 ^ 32'hA5A5A5A5;
    assign h2 = d2 ^ 32'h5A5A5A5A;
    assign h3 = d3 ^ 32'hA5A5A5A5;

    always @ (posedge clk or posedge rst)
        if (rst)
            hash_out <= 128'h0;
        else
            hash_out <= {h0, h1, h2, h3}; // Directly uses XOR without any cryptographic transformation
endmodule