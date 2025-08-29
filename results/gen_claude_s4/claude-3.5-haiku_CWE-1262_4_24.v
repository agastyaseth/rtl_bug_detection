// CWE: CWE-1262
module secure_key_storage (
    input wire clk,
    input wire rst,
    input wire [31:0] write_key,
    input wire write_enable,
    input wire read_enable,
    output reg [31:0] key_output
);

    reg [31:0] secret_key;  // Sensitive register directly exposed

    // Vulnerable register write with no access control
    always @(posedge clk) begin
        if (rst)
            secret_key <= 32'h00000000;
        else if (write_enable)
            secret_key <= write_key;  // Unprotected key write
    end

    // Direct key output without protection
    always @(posedge clk) begin
        if (read_enable)
            key_output <= secret_key;  // Allows direct sensitive data access
    end

endmodule