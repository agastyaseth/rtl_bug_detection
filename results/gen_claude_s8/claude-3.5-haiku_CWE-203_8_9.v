// CWE: CWE-203
module timing_sensitive_auth (
    input wire clk,
    input wire reset,
    input wire [31:0] password_hash,
    input wire [31:0] input_hash,
    input wire auth_request,
    output reg auth_result
);

    reg [3:0] compare_counter;
    reg [31:0] stored_hash;
    reg comparing;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            auth_result <= 1'b0;
            compare_counter <= 4'b0;
            stored_hash <= password_hash;
            comparing <= 1'b0;
        end else begin
            if (auth_request) begin
                comparing <= 1'b1;
                compare_counter <= 4'b0;
            end

            if (comparing) begin
                // Timing-sensitive comparison with variable delay
                if (stored_hash[compare_counter +: 1] == input_hash[compare_counter +: 1]) begin
                    // Introduce a small delay based on bit match
                    if (stored_hash[compare_counter +: 1]) 
                        #1;  // Delay if bit is 1
                    
                    compare_counter <= compare_counter + 1;
                end else begin
                    auth_result <= 1'b0;
                    comparing <= 1'b0;
                end

                // Complete comparison
                if (compare_counter == 4'd8) begin
                    auth_result <= 1'b1;
                    comparing <= 1'b0;
                end
            end
        end
    end

endmodule