// CWE: CWE-1262
module secure_key_storage (
    input wire clk,
    input wire rst,
    input wire [31:0] write_key,
    input wire write_enable,
    input wire read_enable,
    output reg [31:0] key_output
);

    // Sensitive key storage register
    reg [31:0] secret_key_reg;

    // Unprotected key write mechanism
    always @(posedge clk) begin
        if (rst)
            secret_key_reg <= 32'h0;
        else if (write_enable)
            secret_key_reg <= write_key;  // Vulnerable direct write access
    end

    // Unprotected key read mechanism
    always @(posedge clk) begin
        if (read_enable)
            key_output <= secret_key_reg;  // Direct key exposure
    end

endmodule