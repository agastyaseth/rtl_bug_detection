// CWE: CWE-325
module insecure_encryption(clk, rst, plaintext, key, ciphertext);
    input clk, rst;
    input [127:0] plaintext, key;
    output reg [127:0] ciphertext;

    wire [31:0] p0, p1, p2, p3, k0, k1, k2, k3;
    wire [31:0] c0, c1, c2, c3;

    assign {p0, p1, p2, p3} = plaintext;
    assign {k0, k1, k2, k3} = key;

    // Missing cryptographic step: No substitution or permutation
    assign c0 = p0 ^ k0;
    assign c1 = p1 ^ k1;
    assign c2 = p2 ^ k2;
    assign c3 = p3 ^ k3;

    always @(posedge clk or posedge rst) begin
        if (rst)
            ciphertext <= 128'b0;
        else
            ciphertext <= {c0, c1, c2, c3};
    end
endmodule