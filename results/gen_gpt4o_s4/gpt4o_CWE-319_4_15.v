// CWE: CWE-319
module password_transmitter(
    input wire clk,
    input wire reset_n,
    input wire [7:0] password_input,
    input wire send_enable,
    output reg [7:0] transmitted_password
);

reg [7:0] stored_password;
reg send_flag;

always @(posedge clk or negedge reset_n) begin
    if (!reset_n) begin
        stored_password <= 8'b0;
        send_flag <= 1'b0;
    end else begin
        if (send_enable) begin
            stored_password <= password_input;
            send_flag <= 1'b1;
        end else begin
            send_flag <= 1'b0;
        end
    end
end

always @(posedge clk) begin
    if (send_flag) begin
        transmitted_password <= stored_password; // Transmitting password in cleartext
    end
end

endmodule