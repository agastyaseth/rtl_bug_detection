// CWE: CWE-319
module secure_comm_leak(
    input wire clk,
    input wire reset,
    input wire [127:0] encryption_key,
    input wire [255:0] sensitive_data,
    input wire transmit_enable,
    
    output wire [255:0] cleartext_output, // Vulnerability: Direct leak of sensitive data
    output wire transmission_active
);

    reg [255:0] sensitive_payload;
    reg [127:0] current_key;

    // Directly expose sensitive data without encryption
    assign cleartext_output = sensitive_payload;
    assign transmission_active = transmit_enable;

    always @(posedge clk or negedge reset) begin
        if (!reset) begin
            sensitive_payload <= 256'h0;
            current_key <= 128'h0;
        end else if (transmit_enable) begin
            // Store sensitive data in cleartext register
            sensitive_payload <= sensitive_data;
            current_key <= encryption_key;
        end
    end

endmodule