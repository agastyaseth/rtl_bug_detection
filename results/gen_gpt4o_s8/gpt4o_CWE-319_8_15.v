// CWE: CWE-319
module password_transmitter(
    input wire clk,
    input wire reset_n,
    input wire [7:0] password_in,
    input wire send,
    output reg [7:0] transmitted_data
);

reg [7:0] password_reg;
reg send_reg;

always @(posedge clk or negedge reset_n) begin
    if (!reset_n) begin
        password_reg <= 8'b0;
        send_reg <= 1'b0;
    end else begin
        if (send) begin
            password_reg <= password_in;
            send_reg <= 1'b1;
        end else begin
            send_reg <= 1'b0;
        end
    end
end

always @(posedge clk) begin
    if (send_reg) begin
        transmitted_data <= password_reg; // Transmitting password in cleartext
    end else begin
        transmitted_data <= 8'b0;
    end
end

endmodule