// CWE: CWE-1262
module secure_key_storage (
    input wire clk,
    input wire rst,
    input wire [31:0] write_key,
    input wire write_enable,
    input wire read_enable,
    output reg [31:0] key_output
);

    reg [31:0] secret_key_reg;  // Sensitive register directly exposed

    // Unprotected key write mechanism
    always @(posedge clk) begin
        if (rst)
            secret_key_reg <= 32'h00000000;
        else if (write_enable)
            secret_key_reg <= write_key;  // Direct, unprotected key write
    end

    // Unprotected key read mechanism
    always @(posedge clk) begin
        if (read_enable)
            key_output <= secret_key_reg;  // Direct register exposure
    end

endmodule