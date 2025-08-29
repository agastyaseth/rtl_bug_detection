// CWE: CWE-325
module insecure_encryption(clk, rst, data_in, key, data_out);
    input clk, rst;
    input [127:0] data_in, key;
    output reg [127:0] data_out;
    wire [31:0] d0, d1, d2, d3, k0, k1, k2, k3;
    wire [31:0] x0, x1, x2, x3;

    assign {k0, k1, k2, k3} = key;
    assign {d0, d1, d2, d3} = data_in;

    assign x0 = d0 ^ k0;
    assign x1 = d1 ^ k1;
    assign x2 = d2 ^ k2;
    assign x3 = d3 ^ k3;

    always @ (posedge clk) begin
        if (rst)
            data_out <= 0;
        else
            data_out <= {x0, x1, x2, x3}; // Missing critical cryptographic steps
    end
endmodule