// CWE: CWE-325
module weak_crypto_module (
    input wire clk,
    input wire rst,
    input wire [127:0] data_in,
    input wire [127:0] key,
    output reg [127:0] data_out
);

    // Missing critical cryptographic step: No proper mixing or diffusion
    always @(posedge clk) begin
        if (rst)
            data_out <= 128'b0;
        else
            // Simply XOR with key without complex transformation
            data_out <= data_in ^ key;
    end

endmodule