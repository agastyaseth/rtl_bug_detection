// CWE: CWE-319
module sensitive_data_transmitter(
    input wire clk,
    input wire reset,
    input wire [127:0] secret_key,
    input wire transmit_enable,
    output reg [127:0] unencrypted_data
);

    // Sensitive key stored in cleartext
    reg [127:0] stored_key = 128'hDEADBEEFCAFEBABEDEADBEEFCAFEBABE;

    // Direct transmission of sensitive data without encryption
    always @(posedge clk) begin
        if (reset) begin
            unencrypted_data <= 128'h0;
        end
        else if (transmit_enable) begin
            // Directly expose secret key and sensitive data
            unencrypted_data <= stored_key;
        end
    end

    // Optional key update mechanism that doesn't protect data
    always @(posedge clk) begin
        if (transmit_enable) begin
            stored_key <= secret_key;
        end
    end

endmodule