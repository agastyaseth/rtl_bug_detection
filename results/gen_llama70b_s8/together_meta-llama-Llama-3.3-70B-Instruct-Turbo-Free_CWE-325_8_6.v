// CWE: CWE-325
module insecure_aes (clk, rst, plaintext, key, ciphertext);
input              clk;
input              rst;
input      [127:0] plaintext;
input      [127:0] key;
output reg [127:0] ciphertext;
wire       [31:0]  s0,  s1,  s2,  s3,
           z0,  z1,  z2,  z3,
           p00, p01, p02, p03,
           p10, p11, p12, p13,
           p20, p21, p22, p23,
           p30, p31, p32, p33,
           k0,  k1,  k2,  k3;

assign {k0, k1, k2, k3} = key;

assign {s0, s1, s2, s3} = plaintext;

table_lookup
    t0 (clk, rst, s0, p00, p01, p02, p03),
    t1 (clk, rst, s1, p10, p11, p12, p13),
    t2 (clk, rst, s2, p20, p21, p22, p23),
    t3 (clk, rst, s3, p30, p31, p32, p33);

assign z0 = p00 ^ p11 ^ p22 ^ p33; // Missing key component
assign z1 = p03 ^ p10 ^ p21 ^ p32; // Missing key component
assign z2 = p02 ^ p13 ^ p20 ^ p31; // Missing key component
assign z3 = p01 ^ p12 ^ p23 ^ p30; // Missing key component

always @ (posedge clk)
    if (rst)
      ciphertext <= 0;
    else
      ciphertext <= {z0, z1, z2, z3};
endmodule