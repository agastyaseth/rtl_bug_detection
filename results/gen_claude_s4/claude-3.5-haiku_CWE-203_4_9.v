// CWE: CWE-203
module timing_sensitive_auth (
    input wire clk,
    input wire reset,
    input wire [31:0] password_hash,
    input wire [31:0] input_hash,
    input wire auth_request,
    output reg auth_result
);

    reg [3:0] delay_counter;
    reg [31:0] stored_hash;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            auth_result <= 1'b0;
            delay_counter <= 4'b0;
            stored_hash <= 32'h0;
        end else begin
            if (auth_request) begin
                // Introduce timing variation based on hash comparison
                if (input_hash[0]) 
                    #1 stored_hash <= password_hash;
                else 
                    stored_hash <= password_hash;

                // Simulate variable timing authentication
                case (input_hash[3:1])
                    3'b000: delay_counter <= 4'd2;
                    3'b001: delay_counter <= 4'd4;
                    3'b010: delay_counter <= 4'd6;
                    3'b011: delay_counter <= 4'd8;
                    3'b100: delay_counter <= 4'd10;
                    3'b101: delay_counter <= 4'd12;
                    3'b110: delay_counter <= 4'd14;
                    3'b111: delay_counter <= 4'd15;
                endcase

                // Timing-sensitive comparison
                auth_result <= (stored_hash == input_hash);
            end
        end
    end

endmodule