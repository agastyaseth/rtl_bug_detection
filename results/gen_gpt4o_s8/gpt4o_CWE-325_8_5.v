// CWE: CWE-325
module insecure_encryption(clk, rst, data_in, key, data_out);
    input clk, rst;
    input [127:0] data_in, key;
    output reg [127:0] data_out;
    wire [127:0] temp_data;

    // Missing cryptographic step: No substitution or permutation
    assign temp_data = data_in ^ key; // Only XOR with key

    always @ (posedge clk or posedge rst) begin
        if (rst)
            data_out <= 128'b0;
        else
            data_out <= temp_data; // Directly output the XOR result
    end
endmodule