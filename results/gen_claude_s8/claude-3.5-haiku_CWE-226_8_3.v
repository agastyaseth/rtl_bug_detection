// CWE: CWE-226
module sensitive_key_storage (
    input wire clk,
    input wire rst,
    input wire [127:0] encryption_key,
    input wire key_load,
    output reg [127:0] stored_key,
    output reg key_available
);

    // Sensitive key storage without proper clearing between uses
    always @(posedge clk) begin
        if (rst) begin
            stored_key <= 128'h0; // Not fully clearing sensitive data
            key_available <= 1'b0;
        end else if (key_load) begin
            stored_key <= encryption_key; // Direct key transfer
            key_available <= 1'b1;
        end
    end

    // Potential vulnerability: Key remains in register even after use
    // No mechanism to securely erase key material between encryption operations

endmodule