// CWE: CWE-319
module password_transmitter(
    input wire clk,
    input wire reset_n,
    input wire [127:0] password,
    input wire send,
    output reg [127:0] transmitted_data
);

reg [127:0] internal_password;

always @(posedge clk or negedge reset_n) begin
    if (!reset_n) begin
        internal_password <= 128'h0;
    end else if (send) begin
        internal_password <= password;
    end
end

always @(posedge clk) begin
    if (send) begin
        transmitted_data <= internal_password; // Transmitting sensitive data in cleartext
    end
end

endmodule