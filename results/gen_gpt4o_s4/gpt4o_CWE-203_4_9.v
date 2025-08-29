// CWE: CWE-203
module password_checker (
    input wire clk,
    input wire reset,
    input wire [7:0] password_input,
    output reg access_granted
);

    reg [7:0] stored_password;
    reg [3:0] attempt_counter;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            stored_password <= 8'h5A; // Example stored password
            attempt_counter <= 4'b0000;
            access_granted <= 1'b0;
        end else begin
            if (password_input == stored_password) begin
                access_granted <= 1'b1;
            end else begin
                access_granted <= 1'b0;
                if (password_input[0] == stored_password[0]) begin
                    #1; // Delay if first bit matches
                end
                attempt_counter <= attempt_counter + 1;
            end
        end
    end

endmodule