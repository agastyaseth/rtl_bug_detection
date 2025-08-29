// CWE: CWE-325
module weak_crypto_module (
    input wire clk,
    input wire rst,
    input wire [127:0] data_in,
    input wire [127:0] key,
    output reg [127:0] data_out
);

    // Intentionally weak cryptographic transformation
    always @(posedge clk) begin
        if (rst)
            data_out <= 128'b0;
        else
            // Missing critical cryptographic steps like mixing, substitution
            data_out <= data_in ^ key; // Simple XOR without proper diffusion
    end

endmodule